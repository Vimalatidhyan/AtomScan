#!/bin/bash
################################################################################
# Technieum - Phase 7: Change Detection & Alerting
# Compares current scan against baseline, generates delta report & alerts
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase7_change_detection"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
PHASE4_DIR="$OUTPUT_DIR/phase4_vulnscan"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

mkdir -p "$PHASE_DIR"/{baseline,delta,alerts}

PYTHON="${TECHNIEUM_PYTHON:-python3}"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE_STORE="${TECHNIEUM_BASELINE_DIR:-$REPO_ROOT/.baselines}"
mkdir -p "$BASELINE_STORE"

log_info "=== Phase 7: Change Detection & Alerting for $TARGET ==="
log_info "Baseline store: $BASELINE_STORE"

SAFE_TARGET=$(echo "$TARGET" | tr './' '__')
CURRENT_BASELINE_FILE="$BASELINE_STORE/${SAFE_TARGET}_latest.json"
PREVIOUS_BASELINE_FILE="$BASELINE_STORE/${SAFE_TARGET}_previous.json"

# ─── 7A: Snapshot current scan state ──────────────────────────────────────────
log_info "=== 7A: Building current scan snapshot ==="

CURRENT_SNAPSHOT="$PHASE_DIR/baseline/current_snapshot.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/snapshot.log"
import json, sys, os, glob
from datetime import datetime

sys.path.insert(0, '$REPO_ROOT')

snapshot = {
    'target': '$TARGET',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'subdomains': [],
    'open_ports': [],
    'vulnerabilities': [],
    'technologies': [],
}

# Load subdomains from phase 1
subs_file = '$PHASE1_DIR/all_subdomains.txt'
if os.path.exists(subs_file):
    with open(subs_file) as f:
        snapshot['subdomains'] = [l.strip() for l in f if l.strip()]

# Load open ports
for nmap_json in glob.glob('$PHASE4_DIR/*.json'):
    try:
        with open(nmap_json) as f:
            data = json.load(f)
        if isinstance(data, list):
            for h in data:
                if isinstance(h, dict) and 'ports' in h:
                    snapshot['open_ports'].extend(h['ports'])
    except Exception:
        pass

# Load vulnerabilities from phase 4
vuln_file = '$PHASE4_DIR/vulnerabilities_summary.json'
if os.path.exists(vuln_file):
    try:
        with open(vuln_file) as f:
            snapshot['vulnerabilities'] = json.load(f)
    except Exception:
        pass

os.makedirs(os.path.dirname('$CURRENT_SNAPSHOT'), exist_ok=True)
with open('$CURRENT_SNAPSHOT', 'w') as f:
    json.dump(snapshot, f, indent=2)

# Update baseline store
prev = '$PREVIOUS_BASELINE_FILE'
curr = '$CURRENT_BASELINE_FILE'
if os.path.exists(curr):
    import shutil
    shutil.copy2(curr, prev)
with open(curr, 'w') as f:
    json.dump(snapshot, f, indent=2)

print(f"Snapshot: {len(snapshot['subdomains'])} subdomains, {len(snapshot['open_ports'])} ports, {len(snapshot['vulnerabilities'])} vulns")
EOF

# ─── 7B: Baseline management ──────────────────────────────────────────────────
log_info "=== 7B: Baseline management ==="

BASELINE_RESULT="$PHASE_DIR/baseline/baseline_status.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/baseline.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

try:
    from intelligence.change_detection.baseline_manager import BaselineManager
    bm = BaselineManager(baseline_dir='$BASELINE_STORE')
    status = bm.get_status('$TARGET')
except Exception as e:
    print(f"Warning: baseline_manager error: {e}", file=sys.stderr)
    has_baseline = os.path.exists('$PREVIOUS_BASELINE_FILE')
    status = {'has_baseline': has_baseline, 'target': '$TARGET'}

with open('$BASELINE_RESULT', 'w') as f:
    json.dump(status, f, indent=2)
print(f"Baseline status: {status}")
EOF

# ─── 7C: Delta calculation ────────────────────────────────────────────────────
log_info "=== 7C: Computing delta vs previous baseline ==="

DELTA_FILE="$PHASE_DIR/delta/change_delta.json"

if [ -s "$PREVIOUS_BASELINE_FILE" ]; then
    PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/delta.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

try:
    from intelligence.change_detection.calculate_delta import calculate_delta
    with open('$CURRENT_SNAPSHOT') as f:
        current = json.load(f)
    with open('$PREVIOUS_BASELINE_FILE') as f:
        previous = json.load(f)
    delta = calculate_delta(previous, current)
except Exception as e:
    print(f"Warning: calculate_delta error: {e}", file=sys.stderr)
    # Fallback: manual delta
    with open('$CURRENT_SNAPSHOT') as f:
        current = json.load(f)
    with open('$PREVIOUS_BASELINE_FILE') as f:
        previous = json.load(f)
    curr_subs = set(current.get('subdomains', []))
    prev_subs = set(previous.get('subdomains', []))
    delta = {
        'new_subdomains': list(curr_subs - prev_subs),
        'removed_subdomains': list(prev_subs - curr_subs),
        'new_ports': [],
        'removed_ports': [],
        'new_vulnerabilities': [],
        'resolved_vulnerabilities': [],
        'change_severity': 'low',
    }

os.makedirs(os.path.dirname('$DELTA_FILE'), exist_ok=True)
with open('$DELTA_FILE', 'w') as f:
    json.dump(delta, f, indent=2)

new_subs = len(delta.get('new_subdomains', []))
new_ports = len(delta.get('new_ports', []))
new_vulns = len(delta.get('new_vulnerabilities', []))
print(f"Delta: +{new_subs} subdomains, +{new_ports} ports, +{new_vulns} vulns")
EOF
else
    log_info "No previous baseline found — this is the first scan (establishing baseline)"
    echo '{"first_scan": true, "message": "Baseline established — run again to detect changes"}' > "$DELTA_FILE"
fi

# ─── 7D: Alert generation ─────────────────────────────────────────────────────
log_info "=== 7D: Generating change alerts ==="

ALERTS_FILE="$PHASE_DIR/alerts/change_alerts.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/alerts.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

try:
    from intelligence.change_detection.alert_generator import AlertGenerator
    with open('$DELTA_FILE') as f:
        delta = json.load(f)
    ag = AlertGenerator(delta=delta, scan_run_id=0)
    alerts = ag.generate_alerts()
except Exception as e:
    print(f"Warning: alert_generator error: {e}", file=sys.stderr)
    with open('$DELTA_FILE') as f:
        delta = json.load(f)
    alerts = []
    if delta.get('new_subdomains'):
        alerts.append({'severity': 'medium', 'type': 'NEW_SUBDOMAIN', 'count': len(delta['new_subdomains']), 'details': delta['new_subdomains'][:5]})
    if delta.get('new_vulnerabilities'):
        alerts.append({'severity': 'high', 'type': 'NEW_VULNERABILITY', 'count': len(delta['new_vulnerabilities'])})
    if delta.get('new_ports'):
        alerts.append({'severity': 'medium', 'type': 'NEW_PORT_EXPOSED', 'count': len(delta['new_ports'])})

os.makedirs(os.path.dirname('$ALERTS_FILE'), exist_ok=True)
with open('$ALERTS_FILE', 'w') as f:
    json.dump(alerts, f, indent=2)

critical = [a for a in alerts if a.get('severity') == 'critical']
high = [a for a in alerts if a.get('severity') == 'high']
print(f"Alerts generated: {len(alerts)} total ({len(critical)} critical, {len(high)} high)")
EOF

# ─── 7E: Summary ──────────────────────────────────────────────────────────────
log_info "=== 7E: Change detection summary ==="

python3 - <<EOF
import json, os
from datetime import datetime

summary = {
    'target': '$TARGET',
    'phase': 'change_detection',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'delta_computed': os.path.exists('$DELTA_FILE'),
    'alerts_generated': 0,
    'first_scan': False,
}

try:
    with open('$DELTA_FILE') as f:
        delta = json.load(f)
    summary['first_scan'] = delta.get('first_scan', False)
    summary['new_subdomains'] = len(delta.get('new_subdomains', []))
    summary['new_ports'] = len(delta.get('new_ports', []))
    summary['new_vulnerabilities'] = len(delta.get('new_vulnerabilities', []))
except Exception:
    pass

try:
    with open('$ALERTS_FILE') as f:
        alerts = json.load(f)
    summary['alerts_generated'] = len(alerts)
except Exception:
    pass

with open('$PHASE_DIR/change_detection_summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
EOF

log_info "=== Phase 7 complete: Change detection results in $PHASE_DIR ==="
