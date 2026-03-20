#!/bin/bash
################################################################################
# Technieum - Phase 6: CVE Correlation & Risk Scoring
# Correlates discovered services/versions with CVE databases, scores risk
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase6_cve_correlation"
PHASE2_DIR="$OUTPUT_DIR/phase2_intel"
PHASE4_DIR="$OUTPUT_DIR/phase4_vulnscan"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

mkdir -p "$PHASE_DIR"/{cve_data,risk_scores,exploits,kev_matches}

log_info "=== Phase 6: CVE Correlation & Risk Scoring for $TARGET ==="
log_info "Output directory: $PHASE_DIR"

PYTHON="${TECHNIEUM_PYTHON:-python3}"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── 6A: Extract service/version inventory ────────────────────────────────────
log_info "=== 6A: Building service/version inventory ==="

SERVICES_FILE="$PHASE_DIR/services_inventory.json"

# Pull from nmap XML output (phase2 is where nmap runs)
NMAP_XML=""
if [ -s "$PHASE2_DIR/ports/nmap_all.xml" ]; then
    NMAP_XML="$PHASE2_DIR/ports/nmap_all.xml"
elif [ -s "$PHASE4_DIR/nmap_scan.xml" ]; then
    NMAP_XML="$PHASE4_DIR/nmap_scan.xml"
elif [ -s "$OUTPUT_DIR/nmap.xml" ]; then
    NMAP_XML="$OUTPUT_DIR/nmap.xml"
fi

if [ -n "$NMAP_XML" ]; then
    python3 - <<'EOF' "$NMAP_XML" "$SERVICES_FILE"
import sys, json, xml.etree.ElementTree as ET

nmap_xml, out_file = sys.argv[1], sys.argv[2]
services = []
try:
    tree = ET.parse(nmap_xml)
    for host in tree.findall('.//host'):
        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get('addr') if addr_el is not None else 'unknown'
        for port in host.findall('.//port'):
            svc = port.find('service')
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                services.append({
                    'ip': ip,
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'service': svc.get('name', '') if svc is not None else '',
                    'product': svc.get('product', '') if svc is not None else '',
                    'version': svc.get('version', '') if svc is not None else '',
                    'cpe': svc.get('cpe', '') if svc is not None else ''
                })
except Exception as e:
    print(f"Warning: {e}", file=sys.stderr)

with open(out_file, 'w') as f:
    json.dump(services, f, indent=2)
print(f"Extracted {len(services)} services")
EOF
else
    log_warn "No nmap XML found — creating empty inventory"
    echo "[]" > "$SERVICES_FILE"
fi

SERVICE_COUNT=$(python3 -c "import json; d=json.load(open('$SERVICES_FILE')); print(len(d))" 2>/dev/null || echo "0")
log_info "Inventory: $SERVICE_COUNT services/ports"

# ─── 6B: CVE lookup via Python intelligence module ────────────────────────────
log_info "=== 6B: CVE correlation via intelligence modules ==="

CVE_RESULTS="$PHASE_DIR/cve_data/cve_matches.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/cve_correlation.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

services_file = '$SERVICES_FILE'
output_file = '$CVE_RESULTS'

with open(services_file) as f:
    services = json.load(f)

results = []
for svc in services:
    cpe = svc.get('cpe', '')
    product = svc.get('product', '')
    version = svc.get('version', '')
    if not (cpe or product):
        continue
    # Try risk_scoring module (KEVChecker class)
    try:
        from intelligence.risk_scoring.kev import KEVChecker
        _kev_checker = KEVChecker()
        kev = _kev_checker.check_cve(cpe) if cpe else None
        kev = kev or {'in_kev': False}
    except Exception:
        kev = {'in_kev': False}
    results.append({
        'service': svc,
        'kev_status': kev,
        'cve_count': 0,  # populated by NVD API if key available
        'risk_level': 'high' if kev.get('in_kev') else 'medium'
    })

os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)
print(f"CVE correlation complete: {len(results)} services analysed")
EOF

# Check NVD API key for enrichment
if [ -n "$NVD_API_KEY" ] && command -v curl &>/dev/null; then
    log_info "NVD API key found — enriching CVE data"
    while IFS= read -r cpe; do
        [ -z "$cpe" ] && continue
        safe_filename=$(echo "$cpe" | tr ':/' '__')
        curl -sS --max-time 20 \
            -H "apiKey: $NVD_API_KEY" \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$cpe'))")" \
            -o "$PHASE_DIR/cve_data/${safe_filename}.json" 2>>"$PHASE_DIR/cve_correlation.log" || true
        sleep 0.6  # NVD rate limit
    done < <(python3 -c "
import json
with open('$SERVICES_FILE') as f:
    svcs = json.load(f)
for s in svcs:
    if s.get('cpe'):
        print(s['cpe'])
" 2>/dev/null)
else
    log_warn "NVD_API_KEY not set — skipping NVD enrichment"
fi

# ─── 6C: Risk scoring via Python module ───────────────────────────────────────
log_info "=== 6C: Computing composite risk scores ==="

RISK_SCORES_FILE="$PHASE_DIR/risk_scores/risk_summary.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/risk_scoring.log"
import json, sys
sys.path.insert(0, '$REPO_ROOT')

try:
    from intelligence.risk_scoring.calculate import calculate_risk_scores
    cve_file = '$CVE_RESULTS'
    with open(cve_file) as f:
        cve_data = json.load(f)
    # calculate_risk_scores expects (findings, assets, asset_metadata, kev_data, epss_data, threat_intel)
    scores = calculate_risk_scores(
        findings=cve_data,
        assets=[],
        asset_metadata={},
        kev_data={},
        epss_data={},
        threat_intel=[],
    )
except Exception as e:
    print(f"Warning: risk_scoring module error: {e}", file=sys.stderr)
    scores = {'error': str(e), 'total_scored': 0}

import os
os.makedirs('$PHASE_DIR/risk_scores', exist_ok=True)
with open('$RISK_SCORES_FILE', 'w') as f:
    json.dump(scores, f, indent=2)
print(f"Risk scoring complete")
EOF

# ─── 6D: EPSS scores (if NVD API key available) ───────────────────────────────
log_info "=== 6D: EPSS exploit probability scores ==="

EPSS_FILE="$PHASE_DIR/risk_scores/epss_scores.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/epss.log"
import json, sys
sys.path.insert(0, '$REPO_ROOT')

try:
    from intelligence.risk_scoring.epss import EPSSClient
    _epss = EPSSClient()
    cve_ids = []
    cve_file = '$CVE_RESULTS'
    with open(cve_file) as f:
        cve_data = json.load(f)
    for item in cve_data:
        for cve in item.get('cves', []):
            cve_ids.append(cve.get('id', ''))
    epss = _epss.lookup_multiple(cve_ids) if cve_ids else {}
except Exception as e:
    print(f"Warning: EPSS module error: {e}", file=sys.stderr)
    epss = {}

with open('$EPSS_FILE', 'w') as f:
    json.dump(epss, f, indent=2)
print(f"EPSS scoring complete: {len(epss)} scores")
EOF

# ─── 6E: Summary report ───────────────────────────────────────────────────────
log_info "=== 6E: Generating CVE correlation summary ==="

SUMMARY_FILE="$PHASE_DIR/cve_summary.json"
python3 - <<EOF
import json, os, glob
from datetime import datetime

summary = {
    'target': '$TARGET',
    'phase': 'cve_correlation',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'services_analysed': 0,
    'cve_files': 0,
    'risk_scoring_complete': os.path.exists('$RISK_SCORES_FILE'),
    'epss_scoring_complete': os.path.exists('$EPSS_FILE'),
}

try:
    with open('$SERVICES_FILE') as f:
        summary['services_analysed'] = len(json.load(f))
except Exception:
    pass

cve_files = glob.glob('$PHASE_DIR/cve_data/*.json')
summary['cve_files'] = len(cve_files)

with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
EOF

log_info "=== Phase 6 complete: CVE correlation results in $PHASE_DIR ==="
