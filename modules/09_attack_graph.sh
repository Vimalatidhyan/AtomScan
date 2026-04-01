#!/bin/bash
################################################################################
# Technieum - Phase 9: Attack Surface Graph Construction
# Builds a relationship graph of assets, vulnerabilities, and attack paths
################################################################################

set +e
set -o pipefail

TARGET="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_dir>"
    exit 1
fi

PHASE_DIR="$OUTPUT_DIR/phase9_attack_graph"
PHASE1_DIR="$OUTPUT_DIR/phase1_discovery"
PHASE2_DIR="$OUTPUT_DIR/phase2_intel"
PHASE4_DIR="$OUTPUT_DIR/phase4_vulnscan"
PHASE5_DIR="$OUTPUT_DIR/phase5_threat_intel"
PHASE6_DIR="$OUTPUT_DIR/phase6_cve_correlation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

mkdir -p "$PHASE_DIR"/{graph,paths,visualizations,reports}

PYTHON="${TECHNIEUM_PYTHON:-python3}"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info "=== Phase 9: Attack Surface Graph Construction for $TARGET ==="
log_info "Output directory: $PHASE_DIR"

# ─── 9A: Collect all asset data ───────────────────────────────────────────────
log_info "=== 9A: Collecting asset data from all phases ==="

ASSETS_FILE="$PHASE_DIR/graph/all_assets.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/collect_assets.log"
import json, sys, os, glob
from datetime import datetime

sys.path.insert(0, '$REPO_ROOT')

assets = {
    'target': '$TARGET',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'nodes': [],
    'relationships': [],
}

node_id = 0

def add_node(node_type, identifier, **props):
    global node_id
    n = {'id': node_id, 'type': node_type, 'identifier': identifier, **props}
    assets['nodes'].append(n)
    node_id += 1
    return n['id']

def add_edge(src, dst, rel_type, **props):
    assets['relationships'].append({'source': src, 'target': dst, 'type': rel_type, **props})

# Root domain node
root_id = add_node('domain', '$TARGET', is_root=True)

# Subdomains from phase 1
subs_file = '$PHASE1_DIR/all_subdomains.txt'
sub_ids = {}
if os.path.exists(subs_file):
    with open(subs_file) as f:
        for sub in f:
            sub = sub.strip()
            if sub and sub != '$TARGET':
                sid = add_node('subdomain', sub)
                sub_ids[sub] = sid
                add_edge(root_id, sid, 'HAS_SUBDOMAIN')

# Open ports/services from nmap
for nmap_file in glob.glob('$PHASE4_DIR/*.json'):
    try:
        with open(nmap_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            for host in data:
                if not isinstance(host, dict):
                    continue
                ip = host.get('ip', host.get('address', ''))
                if not ip:
                    continue
                ip_id = add_node('ip_address', ip)
                # Link to subdomain if known
                hostname = host.get('hostname', '')
                if hostname in sub_ids:
                    add_edge(sub_ids[hostname], ip_id, 'RESOLVES_TO')
                else:
                    add_edge(root_id, ip_id, 'HAS_IP')
                for port in host.get('ports', []):
                    port_id = add_node('port', f"{ip}:{port.get('port')}",
                                       port=port.get('port'), protocol=port.get('protocol'),
                                       service=port.get('service'), state=port.get('state'))
                    add_edge(ip_id, port_id, 'HAS_PORT')
    except Exception:
        pass

# Vulnerabilities from phase 4
vuln_file = '$PHASE4_DIR/vulnerabilities_summary.json'
if os.path.exists(vuln_file):
    try:
        with open(vuln_file) as f:
            vulns = json.load(f)
        for vuln in (vulns if isinstance(vulns, list) else []):
            vid = add_node('vulnerability',
                            vuln.get('id', vuln.get('name', f"vuln_{node_id}")),
                            severity=vuln.get('severity', 'unknown'),
                            cvss=vuln.get('cvss_score', 0))
            # Link to affected host/port
            affected = vuln.get('host', vuln.get('target', ''))
            # Find the closest node
            for n in assets['nodes']:
                if n.get('identifier', '') == affected:
                    add_edge(n['id'], vid, 'IS_VULNERABLE_TO')
                    break
            else:
                add_edge(root_id, vid, 'IS_VULNERABLE_TO')
    except Exception:
        pass

with open('$ASSETS_FILE', 'w') as f:
    json.dump(assets, f, indent=2)
print(f"Asset graph: {len(assets['nodes'])} nodes, {len(assets['relationships'])} edges")
EOF

# ─── 9B: Build relationship graph ─────────────────────────────────────────────
log_info "=== 9B: Building relationship graph ==="

GRAPH_FILE="$PHASE_DIR/graph/attack_graph.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/build_graph.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

with open('$ASSETS_FILE') as f:
    assets = json.load(f)

try:
    from intelligence.graph.build_relationships import build_relationships
    # build_relationships expects scan_data dict with domain/subdomains/ports/vulnerabilities keys
    scan_data = {
        'domain': '$TARGET',
        'subdomains': [n['identifier'] for n in assets.get('nodes', []) if n.get('type') == 'subdomain'],
        'dns_records': [],
        'ports': [n for n in assets.get('nodes', []) if n.get('type') == 'port'],
        'vulnerabilities': [n for n in assets.get('nodes', []) if n.get('type') == 'vulnerability'],
    }
    relationships = build_relationships(scan_data)
except Exception as e:
    print(f"Warning: build_relationships error: {e}", file=sys.stderr)
    relationships = assets.get('relationships', [])

try:
    from intelligence.graph.build_graph import build_graph
    # build_graph expects (relationships, return_format)
    graph = build_graph(relationships, return_format="dict")
    if not isinstance(graph, dict):
        graph = {'nodes': assets['nodes'], 'edges': relationships}
except Exception as e:
    print(f"Warning: build_graph error: {e}", file=sys.stderr)
    graph = {'nodes': assets['nodes'], 'edges': relationships, 'error': str(e)}

with open('$GRAPH_FILE', 'w') as f:
    json.dump(graph, f, indent=2)
print(f"Graph built: {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges")
EOF

# ─── 9C: Analyze attack paths ─────────────────────────────────────────────────
log_info "=== 9C: Analyzing attack paths ==="

PATHS_FILE="$PHASE_DIR/paths/attack_paths.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/paths.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

with open('$GRAPH_FILE') as f:
    graph = json.load(f)

try:
    from intelligence.graph.analyze_paths import analyze_critical_paths
    paths_list = analyze_critical_paths(graph)
    paths = {
        'attack_paths': paths_list,
        'entry_points': [n.get('identifier') for n in graph.get('nodes', []) if n.get('type') == 'port'],
        'critical_assets': [n.get('identifier') for n in graph.get('nodes', []) if n.get('severity') in ('critical', 'high')],
    }
except Exception as e:
    print(f"Warning: analyze_paths error: {e}", file=sys.stderr)
    # Fallback: identify high-severity vulnerability nodes as attack entry points
    nodes = graph.get('nodes', [])
    critical_nodes = [n for n in nodes if n.get('severity') in ('critical', 'high')]
    paths = {
        'attack_paths': [],
        'entry_points': [n.get('identifier') for n in nodes if n.get('type') == 'port'],
        'critical_assets': [n.get('identifier') for n in critical_nodes],
        'error': str(e)
    }

os.makedirs(os.path.dirname('$PATHS_FILE'), exist_ok=True)
with open('$PATHS_FILE', 'w') as f:
    json.dump(paths, f, indent=2)

entry_pts = len(paths.get('entry_points', []))
crit = len(paths.get('critical_assets', []))
print(f"Attack paths: {entry_pts} entry points, {crit} critical assets")
EOF

# ─── 9D: Export graph for visualization ───────────────────────────────────────
log_info "=== 9D: Exporting graph for visualization ==="

VIZ_FILE="$PHASE_DIR/visualizations/graph.graphml"
VIZ_JSON="$PHASE_DIR/visualizations/graph_d3.json"

PYTHONPATH="$REPO_ROOT" $PYTHON - <<EOF 2>>"$PHASE_DIR/viz.log"
import json, sys, os
sys.path.insert(0, '$REPO_ROOT')

with open('$GRAPH_FILE') as f:
    graph = json.load(f)

os.makedirs('$PHASE_DIR/visualizations', exist_ok=True)

# Try intelligence graph visualize module
try:
    from intelligence.graph.visualize import visualize_graph
    visualize_graph(graph, '$VIZ_FILE', fmt='graphml')
    visualize_graph(graph, '$VIZ_JSON', fmt='json')
except Exception as e:
    print(f"Warning: visualization module error: {e}", file=sys.stderr)
    # Fallback: D3-compatible JSON
    nodes = graph.get('nodes', [])
    edges = graph.get('edges', graph.get('relationships', []))
    d3 = {
        'nodes': [{'id': str(n.get('id', i)), 'label': n.get('identifier', ''), 'type': n.get('type', '')}
                  for i, n in enumerate(nodes)],
        'links': [{'source': str(e.get('source', '')), 'target': str(e.get('target', '')), 'type': e.get('type', '')}
                  for e in edges]
    }
    with open('$VIZ_JSON', 'w') as f:
        json.dump(d3, f, indent=2)

print(f"Visualization exported: {os.path.exists('$VIZ_JSON')}")
EOF

# ─── 9E: Final summary ────────────────────────────────────────────────────────
log_info "=== 9E: Generating attack graph summary ==="

GRAPH_SUMMARY="$PHASE_DIR/reports/attack_graph_summary.json"

python3 - <<EOF
import json, os
from datetime import datetime

summary = {
    'target': '$TARGET',
    'phase': 'attack_graph',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'graph_nodes': 0,
    'graph_edges': 0,
    'entry_points': 0,
    'critical_assets': 0,
    'attack_paths': 0,
    'visualization_ready': os.path.exists('$VIZ_JSON'),
}

try:
    with open('$ASSETS_FILE') as f:
        assets = json.load(f)
    summary['graph_nodes'] = len(assets.get('nodes', []))
    summary['graph_edges'] = len(assets.get('relationships', []))
except Exception:
    pass

try:
    with open('$PATHS_FILE') as f:
        paths = json.load(f)
    summary['entry_points'] = len(paths.get('entry_points', []))
    summary['critical_assets'] = len(paths.get('critical_assets', []))
    summary['attack_paths'] = len(paths.get('attack_paths', []))
except Exception:
    pass

os.makedirs(os.path.dirname('$GRAPH_SUMMARY'), exist_ok=True)
with open('$GRAPH_SUMMARY', 'w') as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
EOF

log_info "=== Phase 9 complete: Attack graph results in $PHASE_DIR ==="
log_info "=== View graph: $VIZ_JSON ==="
