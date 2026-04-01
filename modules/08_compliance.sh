#!/bin/bash
################################################################################
# Technieum - Phase 8: Compliance Framework Mapping
# Maps discovered findings to PCI-DSS, HIPAA, GDPR, SOC2, NIST CSF controls
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase8_compliance"
PHASE4_DIR="$OUTPUT_DIR/phase4_vulnscan"
PHASE6_DIR="$OUTPUT_DIR/phase6_cve_correlation"
PHASE7_DIR="$OUTPUT_DIR/phase7_change_detection"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

mkdir -p "$PHASE_DIR"/{pci_dss,hipaa,gdpr,soc2,nist_csf,reports}

PYTHON="${TECHNIEUM_PYTHON:-python3}"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info "=== Phase 8: Compliance Mapping for $TARGET ==="
log_info "Output directory: $PHASE_DIR"

# ─── 8A: Aggregate findings from previous phases ──────────────────────────────
log_info "=== 8A: Aggregating findings for compliance mapping ==="

AGGREGATED_FINDINGS="$PHASE_DIR/aggregated_findings.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/aggregate.log"
import json, sys, os, glob
from datetime import datetime

sys.path.insert(0, '$REPO_ROOT')

findings = {
    'target': '$TARGET',
    'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
    'vulnerabilities': [],
    'open_ports': [],
    'risk_scores': {},
    'tls_issues': [],
    'weak_ciphers': [],
    'exposed_sensitive_paths': [],
    'missing_headers': [],
    'data_exposure': [],
}

# Load vulnerabilities from phase 4
for vuln_file in glob.glob('$PHASE4_DIR/**/*.json', recursive=True):
    try:
        with open(vuln_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            findings['vulnerabilities'].extend(data)
        elif isinstance(data, dict) and 'vulnerabilities' in data:
            findings['vulnerabilities'].extend(data['vulnerabilities'])
    except Exception:
        pass

# Load risk scores from phase 6
risk_file = '$PHASE6_DIR/risk_scores/risk_summary.json'
if os.path.exists(risk_file):
    try:
        with open(risk_file) as f:
            findings['risk_scores'] = json.load(f)
    except Exception:
        pass

with open('$AGGREGATED_FINDINGS', 'w') as f:
    json.dump(findings, f, indent=2)
print(f"Aggregated {len(findings['vulnerabilities'])} vulnerabilities for compliance mapping")
EOF

# ─── 8B: Map to compliance frameworks via Python module ───────────────────────
log_info "=== 8B: Mapping findings to compliance frameworks ==="

FRAMEWORKS=("pci_dss" "hipaa" "gdpr" "soc2" "nist_csf")

for FRAMEWORK in "${FRAMEWORKS[@]}"; do
    FRAMEWORK_RESULT="$PHASE_DIR/${FRAMEWORK}/mapping.json"
    log_info "  Mapping to ${FRAMEWORK^^}..."

    PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/${FRAMEWORK}.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

framework = '$FRAMEWORK'
findings_file = '$AGGREGATED_FINDINGS'
output_file = '$FRAMEWORK_RESULT'

with open(findings_file) as f:
    findings = json.load(f)

try:
    from intelligence.compliance.map_findings import map_findings_to_compliance
    result = map_findings_to_compliance(findings, framework=framework)
except Exception as e:
    print(f"Warning: compliance module error for {framework}: {e}", file=sys.stderr)
    try:
        module_path = f'intelligence.compliance.frameworks.{framework}'
        import importlib
        fw_module = importlib.import_module(module_path)
        result = fw_module.check_compliance(findings) if hasattr(fw_module, 'check_compliance') else {'framework': framework, 'error': str(e)}
    except Exception as e2:
        result = {
            'framework': framework,
            'target': '$TARGET',
            'controls_checked': 0,
            'controls_passed': 0,
            'controls_failed': 0,
            'compliance_percentage': 0,
            'findings_mapped': len(findings.get('vulnerabilities', [])),
            'error': f'{e} | {e2}'
        }

os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w') as f:
    json.dump(result, f, indent=2)

pct = result.get('compliance_percentage', result.get('overall_compliance', 'N/A'))
print(f"{framework.upper()}: compliance={pct}%")
EOF
done

# ─── 8C: TLS/cipher compliance check ─────────────────────────────────────────
log_info "=== 8C: TLS and cipher compliance check ==="

TLS_RESULT="$PHASE_DIR/tls_compliance.json"

if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    TESTSSL=$(command -v testssl.sh || command -v testssl)
    log_info "Running testssl.sh against $TARGET:443"
    $TESTSSL --jsonfile "$PHASE_DIR/testssl_raw.json" \
        --severity LOW --fast --quiet \
        "$TARGET:443" 2>>"$PHASE_DIR/testssl.log" || true

    python3 - <<PYEOF
import json, os

raw_file = '$PHASE_DIR/testssl_raw.json'
tls_issues = []

if os.path.exists(raw_file):
    try:
        with open(raw_file) as f:
            data = json.load(f)
        for finding in data.get('findings', []):
            if finding.get('severity', '').upper() in ('HIGH', 'CRITICAL', 'MEDIUM'):
                tls_issues.append({
                    'id': finding.get('id'),
                    'severity': finding.get('severity'),
                    'finding': finding.get('finding'),
                })
    except Exception as e:
        tls_issues = [{'error': str(e)}]

with open('$TLS_RESULT', 'w') as f:
    json.dump({'tls_issues': tls_issues, 'count': len(tls_issues)}, f, indent=2)
print(f"TLS check: {len(tls_issues)} issues found")
PYEOF
else
    log_warn "testssl.sh not found — skipping TLS compliance check"
    echo '{"tls_issues": [], "note": "testssl.sh not installed"}' > "$TLS_RESULT"
fi

# ─── 8D: Compliance summary report ───────────────────────────────────────────
log_info "=== 8D: Generating compliance summary ==="

COMPLIANCE_REPORT="$PHASE_DIR/reports/compliance_summary.json"

python3 - <<EOF
import json, os, glob
from datetime import datetime

summary = {
    'target': '$TARGET',
    'phase': 'compliance_mapping',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'frameworks': {},
    'overall_risk': 'unknown',
    'tls_issues': 0,
}

# Load framework results
frameworks = ['pci_dss', 'hipaa', 'gdpr', 'soc2', 'nist_csf']
for fw in frameworks:
    fw_file = f'$PHASE_DIR/{fw}/mapping.json'
    if os.path.exists(fw_file):
        try:
            with open(fw_file) as f:
                data = json.load(f)
            summary['frameworks'][fw] = {
                'compliance_percentage': data.get('compliance_percentage', data.get('overall_compliance', 0)),
                'controls_failed': data.get('controls_failed', 0),
                'status': 'mapped'
            }
        except Exception:
            summary['frameworks'][fw] = {'status': 'error'}
    else:
        summary['frameworks'][fw] = {'status': 'not_run'}

# TLS issues
tls_file = '$TLS_RESULT'
if os.path.exists(tls_file):
    try:
        with open(tls_file) as f:
            tls = json.load(f)
        summary['tls_issues'] = tls.get('count', 0)
    except Exception:
        pass

# Overall risk
scores = [v.get('compliance_percentage', 100) for v in summary['frameworks'].values() if isinstance(v, dict)]
if scores:
    avg = sum(scores) / len(scores)
    summary['average_compliance'] = round(avg, 1)
    summary['overall_risk'] = 'critical' if avg < 50 else 'high' if avg < 70 else 'medium' if avg < 85 else 'low'

os.makedirs(os.path.dirname('$COMPLIANCE_REPORT'), exist_ok=True)
with open('$COMPLIANCE_REPORT', 'w') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
EOF

log_info "=== Phase 8 complete: Compliance results in $PHASE_DIR ==="
