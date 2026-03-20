/**
 * Technieum Enterprise — Attack Graph Visualization v2.1
 * Shows ALL phase results in the attack graph when a completed scan target is selected.
 *
 * Wired to:
 *   GET /api/v1/scans?status=completed   — list completed scan targets
 *   GET /api/v1/assets/graph/{target}     — full attack graph with all phases
 *
 * Uses D3.js v7 force-directed graph.
 */

const API = '/api/v1';

function ensureApiKey() {
  /* No-op: API key auth disabled. */
}

let state = {
  targets: [],
  selectedTarget: '',
  graphData: null,        // raw API response
  visibleNodes: [],
  visibleLinks: [],
  simulation: null,
  svg: null,
  g: null,
  zoom: null,
  selectedNode: null,
  highlightedNode: null,  // currently highlighted node for relationship view
  // Phase visibility toggles
  phases: {
    phase1_discovery: true,
    phase2_intel: true,
    phase3_content: true,
    phase4_vulnscan: true,
    phase5_threat: true,
    phase7_compliance: true,
  },
  // Per-type visibility toggles
  typeVisibility: { target:true, subdomain:true, dns_record:true, ip_address:true, technology:true, port:true, vulnerability:true, threat_intel:true, compliance:true, asn:true, ssl_cert:true, url:true },
  // Category solo mode: null = show all visible, 'type_name' = solo that type
  soloType: null,
};

// ─── Color & Size Maps ────────────────────────────────────────────────────────
const COLOR_MAP = {
  target:         '#F59E0B',  // Yellow
  subdomain:      '#3B82F6',  // Blue
  dns_record:     '#06B6D4',  // Cyan
  ip_address:     '#60A5FA',  // Light Blue
  technology:     '#8B5CF6',  // Purple
  port:           '#7C3AED',  // Violet
  vulnerability:  '#EF4444',  // Red
  threat_intel:   '#EA580C',  // Dark Orange
  compliance:     '#10B981',  // Green
  asn:            '#22C55E',  // Green
  ssl_cert:       '#E879F9',  // Pink
  url:            '#FB923C',  // Orange
};

const TYPE_LABELS = {
  target: 'Target', subdomain: 'Subdomain', dns_record: 'DNS Record',
  ip_address: 'IP Address', technology: 'Technology', port: 'Port',
  vulnerability: 'Vulnerability', threat_intel: 'Threat Intel',
  compliance: 'Compliance', asn: 'ASN', ssl_cert: 'SSL Cert', url: 'URL',
};

const MAX_VISIBLE_NODES = 500;

const SEVERITY_COLORS = {
  critical: '#DC2626',
  high:     '#F97316',
  medium:   '#F59E0B',
  low:      '#3B82F6',
  info:     '#6B7280',
};

const SIZE_MAP = {
  target:        30,
  subdomain:     14,
  dns_record:    8,
  ip_address:    10,
  technology:    10,
  port:          8,
  vulnerability: 12,
  threat_intel:  10,
  compliance:    12,
  asn:           12,
  ssl_cert:       9,
  url:            7,
};

function nodeColor(d) {
  if (d.type === 'vulnerability') return SEVERITY_COLORS[d.severity || 'info'] || '#EF4444';
  if (d.type === 'threat_intel') return SEVERITY_COLORS[d.severity || 'info'] || '#F97316';
  return COLOR_MAP[d.type] || '#6B7280';
}

function nodeSize(d) {
  if (d.type === 'vulnerability') {
    const sev = d.severity || 'info';
    return sev === 'critical' ? 18 : sev === 'high' ? 14 : 12;
  }
  return SIZE_MAP[d.type] || 10;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  bindEvents();
  if (typeof d3 === 'undefined') {
    showEmptyState('D3.js failed to load. Check your internet connection.');
    return;
  }
  initGraph();

  // Check if a target was passed via query param (e.g. from dashboard link)
  const params = new URLSearchParams(window.location.search);
  const preselect = params.get('target');

  loadTargets(preselect);
});

function bindEvents() {
  el('targetSelect')?.addEventListener('change', onTargetChange);
  // Phase toggle checkboxes
  ['showPhase1', 'showPhase2', 'showPhase3', 'showPhase4', 'showPhase5', 'showPhase7'].forEach(id => {
    el(id)?.addEventListener('change', onPhaseToggle);
  });
  el('resetGraphBtn')?.addEventListener('click', resetZoom);
  el('exportSvgBtn')?.addEventListener('click', exportSVG);
  el('findPathsBtn')?.addEventListener('click', findAttackPaths);
  el('closeNodePanel')?.addEventListener('click', closeNodePanel);
  el('zoomInBtn')?.addEventListener('click', () => zoomBy(1.4));
  el('zoomOutBtn')?.addEventListener('click', () => zoomBy(0.7));
  el('fitGraphBtn')?.addEventListener('click', fitGraph);
  el('clearHighlightBtn')?.addEventListener('click', clearHighlight);

  // Legend click filtering: click to solo a type, click again to unsolo
  document.querySelectorAll('.legend-item[data-type]').forEach(item => {
    item.addEventListener('click', () => {
      const type = item.dataset.type;
      if (state.soloType === type) {
        state.soloType = null;  // unsolo
      } else {
        state.soloType = type;  // solo this type
      }
      updateLegendHighlight();
      applyFilters();
    });
  });

  // Per-type checkboxes (in filter panel)
  document.querySelectorAll('.type-toggle').forEach(cb => {
    cb.addEventListener('change', () => {
      state.typeVisibility[cb.dataset.type] = cb.checked;
      state.soloType = null;
      updateLegendHighlight();
      applyFilters();
    });
  });

  window.addEventListener('resize', debounce(resizeGraph, 250));
}

// ─── Data Loading ─────────────────────────────────────────────────────────────
async function loadTargets(preselect) {
  try {
    // Load completed scans to show only finished targets
    const scansRes = await apiGet('/scans/?status=completed&per_page=100');
    const scans = scansRes?.scans || scansRes?.items || [];
    // Deduplicate targets, keeping the latest scan per domain
    const targetMap = {};
    scans.forEach(s => {
      const domain = s.domain || s.target;
      if (!targetMap[domain] || (s.completed_at && s.completed_at > (targetMap[domain].completed_at || ''))) {
        targetMap[domain] = s;
      }
    });
    state.targets = Object.keys(targetMap);

    // Also load from /assets/targets as fallback
    if (state.targets.length === 0) {
      const targetsRes = await apiGet('/assets/targets');
      state.targets = targetsRes?.targets || [];
    }

    renderTargetSelect();

    // Auto-select preselected target or first target
    const targetToSelect = preselect || (state.targets.length > 0 ? state.targets[0] : null);
    if (targetToSelect && state.targets.includes(targetToSelect)) {
      state.selectedTarget = targetToSelect;
      el('targetSelect').value = targetToSelect;
      loadGraphData();
    } else if (state.targets.length > 0) {
      state.selectedTarget = state.targets[0];
      el('targetSelect').value = state.selectedTarget;
      loadGraphData();
    } else {
      showEmptyState('No completed scans found. Run an assessment first and wait for it to complete.');
    }
  } catch (err) {
    console.error('Targets load failed:', err);
    showEmptyState('API not connected. Start the server first.');
  }
}

async function loadGraphData() {
  if (!state.selectedTarget) return;
  const target = encodeURIComponent(state.selectedTarget);
  showLoading(true);

  try {
    const data = await apiGet(`/assets/graph/${target}`);
    state.graphData = data;
    applyPhaseFilters();
    renderStats();
  } catch (err) {
    console.error('Graph data load failed:', err);
    // Fallback to old API pattern
    try {
      await loadGraphDataFallback();
    } catch (err2) {
      console.error('Fallback also failed:', err2);
      showEmptyState('Failed to load graph data for this target.');
    }
  } finally {
    showLoading(false);
  }
}

/**
 * Fallback: load data from individual endpoints (old pattern)
 * for backwards compatibility if the graph endpoint isn't available.
 */
async function loadGraphDataFallback() {
  const target = encodeURIComponent(state.selectedTarget);
  const results = await Promise.all([
    apiGet(`/assets/subdomains/${target}`).catch(() => ({ subdomains: [] })),
    apiGet(`/assets/ports/${target}`).catch(() => ({ ports: [] })),
    apiGet(`/findings/${target}`).catch(() => ({ findings: [] }))
  ]);

  const subdomains = results[0]?.subdomains || [];
  const ports = results[1]?.ports || [];
  const findings = results[2]?.findings || [];

  // Build graph data in the same format as the API
  const nodes = [];
  const edges = [];
  const rootId = `target:${state.selectedTarget}`;
  nodes.push({ id: rootId, type: 'target', label: state.selectedTarget, phase: 'root' });

  subdomains.forEach(sub => {
    const host = typeof sub === 'string' ? sub : sub.subdomain || sub.host || sub.name;
    if (!host) return;
    const id = `subdomain:${host}`;
    nodes.push({ id, type: 'subdomain', label: host, phase: 'phase1_discovery', ...sub });
    edges.push({ source: rootId, target: id, type: 'HAS_SUBDOMAIN' });
  });

  ports.forEach(p => {
    const host = p.subdomain || p.host || state.selectedTarget;
    const id = `port:${host}:${p.port}/${p.protocol || 'tcp'}`;
    const parentId = nodes.find(n => n.id === `subdomain:${host}`) ? `subdomain:${host}` : rootId;
    nodes.push({ id, type: 'port', label: `${p.port}/${p.protocol || 'tcp'}`, phase: 'phase4_vulnscan', ...p });
    edges.push({ source: parentId, target: id, type: 'HAS_PORT' });
  });

  findings.forEach((f, i) => {
    const severity = (f.severity || 'info').toLowerCase();
    const id = `vulnerability:vuln:${f.id || i}:${f.name || 'finding'}`;
    const host = f.host || state.selectedTarget;
    const parentId = nodes.find(n => n.id === `subdomain:${host}`) ? `subdomain:${host}` : rootId;
    nodes.push({ id, type: 'vulnerability', label: f.name || f.title || `Finding ${i + 1}`,
                 phase: 'phase4_vulnscan', severity, ...f });
    edges.push({ source: parentId, target: id, type: 'IS_VULNERABLE_TO' });
  });

  state.graphData = {
    target: state.selectedTarget,
    nodes, edges,
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      subdomains: subdomains.length,
      ports: ports.length,
      vulnerabilities: findings.length,
      critical: findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
      high: findings.filter(f => (f.severity || '').toLowerCase() === 'high').length,
      technologies: 0, dns_records: 0, threat_indicators: 0, compliance_reports: 0,
    },
    phases: {},
  };
  applyPhaseFilters();
  renderStats();
}

// ─── Phase Filtering ──────────────────────────────────────────────────────────
function onTargetChange() {
  state.selectedTarget = el('targetSelect')?.value || '';
  if (state.selectedTarget) loadGraphData();
}

function onPhaseToggle() {
  state.phases.phase1_discovery = el('showPhase1')?.checked ?? true;
  state.phases.phase2_intel = el('showPhase2')?.checked ?? true;
  state.phases.phase3_content = el('showPhase3')?.checked ?? true;
  state.phases.phase4_vulnscan = el('showPhase4')?.checked ?? true;
  state.phases.phase5_threat = el('showPhase5')?.checked ?? true;
  state.phases.phase7_compliance = el('showPhase7')?.checked ?? true;
  applyFilters();
}

function applyFilters() {
  if (!state.graphData) return;
  const allNodes = state.graphData.nodes || [];
  const allEdges = state.graphData.edges || [];

  // Determine which types are visible
  const visibleTypes = new Set();
  if (state.soloType) {
    visibleTypes.add('target');  // always show root
    visibleTypes.add(state.soloType);
  } else {
    Object.entries(state.typeVisibility).forEach(([type, visible]) => {
      if (visible) visibleTypes.add(type);
    });
  }

  // Apply phase + type filters
  const visibleNodeIds = new Set();
  state.visibleNodes = allNodes.filter(n => {
    // Root/target always visible
    if (n.phase === 'root' || n.type === 'target') {
      visibleNodeIds.add(n.id);
      return true;
    }
    // Phase filter
    const phase = n.phase || '';
    if (state.phases[phase] === false) return false;
    // Type filter
    if (!visibleTypes.has(n.type)) return false;
    visibleNodeIds.add(n.id);
    return true;
  });

  // When solo mode is active, also include direct neighbors of solo type nodes
  if (state.soloType) {
    const soloNodeIds = new Set(state.visibleNodes.filter(n => n.type === state.soloType).map(n => n.id));
    allEdges.forEach(e => {
      const src = typeof e.source === 'string' ? e.source : e.source?.id;
      const tgt = typeof e.target === 'string' ? e.target : e.target?.id;
      if (soloNodeIds.has(src) || soloNodeIds.has(tgt)) {
        const neighborId = soloNodeIds.has(src) ? tgt : src;
        if (!visibleNodeIds.has(neighborId)) {
          const neighborNode = allNodes.find(n => n.id === neighborId);
          if (neighborNode) {
            visibleNodeIds.add(neighborId);
            state.visibleNodes.push(neighborNode);
          }
        }
      }
    });
  }

  // Enforce max node limit for performance
  if (state.visibleNodes.length > MAX_VISIBLE_NODES) {
    // Prioritize: target, vuln, threat, subdomain, then others
    const priority = { target: 0, vulnerability: 1, threat_intel: 2, subdomain: 3 };
    state.visibleNodes.sort((a, b) => (priority[a.type] ?? 5) - (priority[b.type] ?? 5));
    const trimmed = state.visibleNodes.slice(0, MAX_VISIBLE_NODES);
    visibleNodeIds.clear();
    trimmed.forEach(n => visibleNodeIds.add(n.id));
    state.visibleNodes = trimmed;
    toast(`Showing ${MAX_VISIBLE_NODES} of ${allNodes.length} nodes for performance`, 'info');
  }

  state.visibleLinks = allEdges.filter(e => {
    const src = typeof e.source === 'string' ? e.source : e.source?.id;
    const tgt = typeof e.target === 'string' ? e.target : e.target?.id;
    return visibleNodeIds.has(src) && visibleNodeIds.has(tgt);
  });

  renderGraph();
}

// Keep old name as alias for backwards compatibility
function applyPhaseFilters() { applyFilters(); }

function updateLegendHighlight() {
  document.querySelectorAll('.legend-item[data-type]').forEach(item => {
    if (state.soloType) {
      item.classList.toggle('legend-solo', item.dataset.type === state.soloType);
      item.classList.toggle('legend-dimmed', item.dataset.type !== state.soloType);
    } else {
      item.classList.remove('legend-solo', 'legend-dimmed');
      const visible = state.typeVisibility[item.dataset.type] !== false;
      item.classList.toggle('legend-dimmed', !visible);
    }
  });
}

// ─── D3 Graph ─────────────────────────────────────────────────────────────────
function initGraph() {
  const container = el('graphContainer');
  if (!container) return;
  const width = container.clientWidth;
  const height = container.clientHeight || 650;
  container.style.position = 'relative';

  state.svg = d3.select('#graphContainer')
    .append('svg')
    .attr('width', '100%')
    .attr('height', '100%')
    .attr('viewBox', `0 0 ${width} ${height}`);

  // Arrow markers
  const defs = state.svg.append('defs');
  Object.entries(COLOR_MAP).forEach(([type, color]) => {
    defs.append('marker')
      .attr('id', `arrow-${type}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', color);
  });

  state.g = state.svg.append('g');
  state.zoom = d3.zoom()
    .scaleExtent([0.1, 5])
    .on('zoom', (event) => state.g.attr('transform', event.transform));
  state.svg.call(state.zoom);
}

function renderGraph() {
  if (!state.g) return;
  state.g.selectAll('*').remove();
  state.highlightedNode = null;

  const container = el('graphContainer');
  const width = container.clientWidth;
  const height = container.clientHeight || 650;

  // Deep copy nodes/links for D3 (it mutates them)
  const nodes = state.visibleNodes.map(n => ({ ...n }));
  const links = state.visibleLinks.map(l => ({
    ...l,
    source: typeof l.source === 'string' ? l.source : l.source?.id,
    target: typeof l.target === 'string' ? l.target : l.target?.id,
  }));

  if (nodes.length === 0) {
    showEmptyState('No data to display. Select a target or enable more phases.');
    return;
  }

  // Hide empty state
  const empties = container.querySelectorAll('.graph-empty, #graphEmpty');
  empties.forEach(e => e.style.display = 'none');

  // Simulation — improved forces for less clutter
  if (state.simulation) state.simulation.stop();

  // Cluster centers for each type (radial placement around center)
  const typeList = [...new Set(nodes.map(n => n.type))];
  const clusterCenters = {};
  typeList.forEach((type, i) => {
    const angle = (2 * Math.PI * i) / typeList.length;
    const radius = Math.min(width, height) * 0.3;
    clusterCenters[type] = {
      x: width / 2 + radius * Math.cos(angle),
      y: height / 2 + radius * Math.sin(angle),
    };
  });
  // Target always at center
  clusterCenters.target = { x: width / 2, y: height / 2 };

  state.simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(d => {
      const srcType = typeof d.source === 'object' ? d.source.type : '';
      const tgtType = typeof d.target === 'object' ? d.target.type : '';
      if (srcType === 'target') return 150;
      if (srcType === tgtType) return 40;
      return 80;
    }))
    .force('charge', d3.forceManyBody().strength(d => d.type === 'target' ? -600 : -180))
    .force('center', d3.forceCenter(width / 2, height / 2).strength(0.05))
    .force('collision', d3.forceCollide().radius(d => nodeSize(d) + 12).strength(0.8))
    .force('cluster', d3.forceX(d => clusterCenters[d.type]?.x || width / 2).strength(0.08))
    .force('clusterY', d3.forceY(d => clusterCenters[d.type]?.y || height / 2).strength(0.08));

  // Links
  const link = state.g.append('g').attr('class', 'links-group')
    .selectAll('line')
    .data(links)
    .join('line')
    .attr('stroke', d => {
      const srcType = typeof d.source === 'object' ? d.source.type : '';
      return COLOR_MAP[srcType] || 'rgba(255,255,255,0.08)';
    })
    .attr('stroke-width', 1)
    .attr('stroke-opacity', 0.15);

  // Nodes
  const node = state.g.append('g').attr('class', 'nodes-group')
    .selectAll('g')
    .data(nodes)
    .join('g')
    .attr('class', d => `node-group node-type-${d.type}`)
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', dragStarted)
      .on('drag', dragged)
      .on('end', dragEnded)
    )
    .on('click', (event, d) => {
      event.stopPropagation();
      highlightNode(d, node, link);
      selectNode(d);
    })
    .on('mouseenter', (event, d) => showTooltip(event, d))
    .on('mousemove', (event) => moveTooltip(event))
    .on('mouseleave', () => hideTooltip());

  // Click on background to clear highlight
  state.svg.on('click', () => {
    clearHighlight();
    closeNodePanel();
  });

  // Circles
  node.append('circle')
    .attr('r', d => nodeSize(d))
    .attr('fill', d => nodeColor(d))
    .attr('stroke', d => d3.color(nodeColor(d)).brighter(0.5))
    .attr('stroke-width', 1.5)
    .attr('opacity', 0.9);

  // Glow for critical/high vulnerabilities
  node.filter(d => d.type === 'vulnerability' && (d.severity === 'critical' || d.severity === 'high'))
    .append('circle')
    .attr('r', d => nodeSize(d) + 4)
    .attr('fill', 'none')
    .attr('stroke', d => nodeColor(d))
    .attr('stroke-width', 1.5)
    .attr('opacity', 0.3);

  // Labels — hidden by default, shown on hover via CSS
  node.append('text')
    .attr('class', 'node-label')
    .text(d => truncate(d.label, 22))
    .attr('x', d => nodeSize(d) + 5)
    .attr('y', 4)
    .attr('fill', 'rgba(255,255,255,0.70)')
    .attr('font-size', d => d.type === 'target' ? '12px' : '9px')
    .attr('font-family', 'monospace')
    .attr('pointer-events', 'none')
    .attr('opacity', d => d.type === 'target' ? 1 : 0);  // Only target labels visible by default

  // Show label on hover
  node.on('mouseenter.label', function() {
    d3.select(this).select('.node-label').transition().duration(150).attr('opacity', 1);
  }).on('mouseleave.label', function(event, d) {
    if (d.type !== 'target') {
      d3.select(this).select('.node-label').transition().duration(300).attr('opacity', 0);
    }
  });

  // Tick
  state.simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Store references for highlight
  state._nodeSelection = node;
  state._linkSelection = link;
}

function dragStarted(event, d) {
  if (!event.active) state.simulation.alphaTarget(0.3).restart();
  d.fx = d.x; d.fy = d.y;
}

function dragged(event, d) {
  d.fx = event.x; d.fy = event.y;
}

function dragEnded(event, d) {
  if (!event.active) state.simulation.alphaTarget(0);
  d.fx = null; d.fy = null;
}

function selectNode(d) {
  state.selectedNode = d;
  renderNodePanel(d);
}

// ─── Node Detail Panel ────────────────────────────────────────────────────────
function renderNodePanel(d) {
  const panel = el('nodePanel');
  if (!panel) return;

  el('nodePanelTitle').textContent = d.label;
  const body = el('nodePanelBody');
  let html = '';

  const row = (key, val) => val != null && val !== '' && val !== undefined
    ? `<div class="prop-row"><span class="prop-key">${esc(key)}</span><span class="prop-val">${esc(String(val))}</span></div>`
    : '';

  const phaseLabel = (phase) => {
    const map = {
      root: 'Root', phase1_discovery: 'Phase 1: Discovery', phase2_intel: 'Phase 2: Intel',
      phase3_content: 'Phase 3: Content', phase4_vulnscan: 'Phase 4: Vuln Scan',
      phase5_threat: 'Phase 5: Threat Intel', phase7_compliance: 'Phase 7: Compliance',
    };
    return map[phase] || phase || 'Unknown';
  };

  html += row('Type', d.type);
  html += row('Phase', phaseLabel(d.phase));

  switch (d.type) {
    case 'target':
      html += row('Domain', d.label);
      break;
    case 'subdomain':
      html += row('Host', d.label);
      html += row('Alive', d.is_alive ? 'Yes' : 'No');
      html += row('Method', d.discovered_method);
      html += row('First Seen', d.first_seen);
      break;
    case 'dns_record':
      html += row('Domain', d.domain);
      html += row('Record Type', d.record_type);
      html += row('Value', d.value);
      html += row('TTL', d.ttl);
      break;
    case 'ip_address':
      html += row('IP', d.label);
      html += row('ISP', d.isp);
      html += row('Country', d.country);
      html += row('City', d.city);
      break;
    case 'technology':
      html += row('Name', d.label);
      html += row('Category', d.category);
      html += row('Version', d.version);
      html += row('Confidence', d.confidence != null ? `${d.confidence}%` : null);
      break;
    case 'port':
      html += row('Port', d.port);
      html += row('Protocol', d.protocol);
      html += row('Service', d.service);
      html += row('Version', d.version);
      html += row('State', d.state);
      html += row('Host', d.host);
      break;
    case 'vulnerability':
      html += `<div class="prop-row"><span class="prop-key">Severity</span><span class="prop-val"><span class="badge badge-${d.severity || 'info'}">${(d.severity || 'info').toUpperCase()}</span></span></div>`;
      html += row('Title', d.title);
      html += row('CVE', d.cve);
      html += row('Type', d.vuln_type);
      html += row('Status', d.status);
      if (d.description) {
        html += `<div class="prop-row"><span class="prop-key">Description</span><span class="prop-val" style="white-space:pre-wrap;font-size:0.75rem;">${esc(d.description)}</span></div>`;
      }
      if (d.remediation) {
        html += `<div class="prop-row"><span class="prop-key">Remediation</span><span class="prop-val" style="white-space:pre-wrap;font-size:0.75rem;">${esc(d.remediation)}</span></div>`;
      }
      break;
    case 'threat_intel':
      html += row('Indicator Type', d.indicator_type);
      html += row('Value', d.indicator_value);
      html += row('Source', d.source);
      html += row('Severity', d.severity);
      break;
    case 'compliance':
      html += row('Framework', d.report_type);
      html += row('Passed', d.passed);
      html += row('Failed', d.failed);
      html += row('Score', d.score != null ? `${d.score}%` : null);
      break;
    case 'asn':
      html += row('ASN', d.label);
      html += row('Host Count', d.count);
      break;
    case 'ssl_cert':
      html += row('Hostname', d.hostname);
      html += row('IP', d.ip);
      html += row('Source', d.source);
      break;
    case 'url':
      html += row('URL', d.label);
      html += row('Status', d.status_code);
      html += row('Length', d.length);
      html += row('Source', d.source);
      break;
    default:
      // Show all properties
      Object.entries(d).forEach(([k, v]) => {
        if (k !== 'id' && k !== 'x' && k !== 'y' && k !== 'vx' && k !== 'vy' && k !== 'fx' && k !== 'fy' && k !== 'index') {
          html += row(k, v);
        }
      });
  }

  body.innerHTML = html;
  panel.classList.remove('hidden');
}

function closeNodePanel() {
  const panel = el('nodePanel');
  if (panel) panel.classList.add('hidden');
  state.selectedNode = null;
}

// ─── Tooltip ──────────────────────────────────────────────────────────────────
function showTooltip(event, d) {
  let tip = el('graphTooltip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'graphTooltip';
    tip.className = 'graph-tooltip';
    document.body.appendChild(tip);
  }
  const typeLabel = TYPE_LABELS[d.type] || d.type;
  const color = nodeColor(d);
  let extra = '';
  if (d.type === 'vulnerability' && d.severity) {
    extra = `<div class="tooltip-severity" style="color:${SEVERITY_COLORS[d.severity] || '#6B7280'}">${d.severity.toUpperCase()}</div>`;
  }
  tip.innerHTML = `<div class="tooltip-type" style="color:${color}">${esc(typeLabel)}</div><div class="tooltip-label">${esc(d.label)}</div>${extra}`;
  tip.style.display = 'block';
  moveTooltip(event);
}

function moveTooltip(event) {
  const tip = el('graphTooltip');
  if (!tip) return;
  tip.style.left = (event.pageX + 14) + 'px';
  tip.style.top = (event.pageY - 10) + 'px';
}

function hideTooltip() {
  const tip = el('graphTooltip');
  if (tip) tip.style.display = 'none';
}

// ─── Node Highlight (click to show relationships) ─────────────────────────────
function highlightNode(d, nodeSelection, linkSelection) {
  state.highlightedNode = d;
  const connectedIds = new Set([d.id]);

  // Find all directly connected nodes
  (state.visibleLinks || []).forEach(l => {
    const src = typeof l.source === 'string' ? l.source : l.source?.id;
    const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
    if (src === d.id) connectedIds.add(tgt);
    if (tgt === d.id) connectedIds.add(src);
  });

  // Fade unrelated nodes
  nodeSelection.transition().duration(300)
    .attr('opacity', n => connectedIds.has(n.id) ? 1 : 0.08);

  // Highlight connected edges, fade rest
  linkSelection.transition().duration(300)
    .attr('stroke-opacity', l => {
      const src = typeof l.source === 'string' ? l.source : l.source?.id;
      const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
      return (src === d.id || tgt === d.id) ? 0.7 : 0.02;
    })
    .attr('stroke-width', l => {
      const src = typeof l.source === 'string' ? l.source : l.source?.id;
      const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
      return (src === d.id || tgt === d.id) ? 2 : 0.5;
    });

  // Show labels of connected nodes
  nodeSelection.each(function(n) {
    d3.select(this).select('.node-label')
      .transition().duration(300)
      .attr('opacity', connectedIds.has(n.id) ? 1 : 0);
  });
}

function clearHighlight() {
  state.highlightedNode = null;
  if (state._nodeSelection) {
    state._nodeSelection.transition().duration(300).attr('opacity', 1);
    state._nodeSelection.each(function(d) {
      d3.select(this).select('.node-label')
        .transition().duration(300)
        .attr('opacity', d.type === 'target' ? 1 : 0);
    });
  }
  if (state._linkSelection) {
    state._linkSelection.transition().duration(300)
      .attr('stroke-opacity', 0.15)
      .attr('stroke-width', 1);
  }
}

// ─── Stats ────────────────────────────────────────────────────────────────────
function renderStats() {
  if (!state.graphData) return;
  const s = state.graphData.stats || {};
  animateNum('subdomainCount', s.subdomains || 0);
  animateNum('portCount', s.ports || 0);
  animateNum('dnsCount', s.dns_records || 0);
  animateNum('techCount', s.technologies || 0);
  animateNum('vulnCount', s.vulnerabilities || 0);
  animateNum('threatCount', s.threat_indicators || 0);
  animateNum('nodeCount', s.total_nodes || 0);
  animateNum('edgeCount', s.total_edges || 0);
}

// ─── Zoom Controls ────────────────────────────────────────────────────────────
function resetZoom() {
  if (state.svg && state.zoom) {
    state.svg.transition().duration(500).call(state.zoom.transform, d3.zoomIdentity);
  }
}

function zoomBy(factor) {
  if (state.svg && state.zoom) {
    state.svg.transition().duration(300).call(state.zoom.scaleBy, factor);
  }
}

function fitGraph() {
  if (!state.svg || !state.g || !state.visibleNodes.length) return;
  const container = el('graphContainer');
  const width = container.clientWidth;
  const height = container.clientHeight || 650;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  state.visibleNodes.forEach(n => {
    if (n.x != null && n.y != null) {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    }
  });
  if (!isFinite(minX)) return;

  const pad = 60;
  const gWidth = maxX - minX + pad * 2;
  const gHeight = maxY - minY + pad * 2;
  const scale = Math.min(width / gWidth, height / gHeight, 2);
  const tx = width / 2 - (minX + maxX) / 2 * scale;
  const ty = height / 2 - (minY + maxY) / 2 * scale;

  state.svg.transition().duration(500).call(
    state.zoom.transform,
    d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}

function resizeGraph() {
  const container = el('graphContainer');
  if (!container || !state.svg) return;
  const w = container.clientWidth;
  const h = container.clientHeight || 650;
  state.svg.attr('viewBox', `0 0 ${w} ${h}`);
  if (state.simulation) {
    state.simulation.force('center', d3.forceCenter(w / 2, h / 2));
    state.simulation.alpha(0.3).restart();
  }
}

// ─── Export ───────────────────────────────────────────────────────────────────
function exportSVG() {
  if (!state.svg) return;
  const svgEl = state.svg.node();
  const serializer = new XMLSerializer();
  const svgStr = serializer.serializeToString(svgEl);
  const blob = new Blob([svgStr], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `technieum-graph-${state.selectedTarget || 'export'}.svg`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Graph exported as SVG', 'success');
}

// ─── Attack Paths ──────────────────────────────────────────────────────────────
function findAttackPaths() {
  if (!state.visibleNodes || state.visibleNodes.length === 0) {
    toast('Load a graph first before finding attack paths', 'warning');
    return;
  }
  const criticalNodes = state.visibleNodes.filter(n =>
    n.type === 'vulnerability' && (n.severity === 'critical' || n.severity === 'high')
  );
  if (criticalNodes.length === 0) {
    toast('No critical or high severity findings found', 'info');
    return;
  }
  const criticalIds = new Set(criticalNodes.map(n => n.id));
  const pathLinks = state.visibleLinks.filter(l => {
    const src = typeof l.source === 'string' ? l.source : l.source?.id;
    const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
    return criticalIds.has(src) || criticalIds.has(tgt);
  });
  const pathNodeIds = new Set();
  pathLinks.forEach(l => {
    pathNodeIds.add(typeof l.source === 'string' ? l.source : l.source?.id);
    pathNodeIds.add(typeof l.target === 'string' ? l.target : l.target?.id);
  });

  if (state._nodeSelection && state._linkSelection) {
    state._linkSelection.attr('stroke-opacity', l => {
      const src = typeof l.source === 'string' ? l.source : l.source?.id;
      const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
      return (criticalIds.has(src) || criticalIds.has(tgt)) ? 0.8 : 0.02;
    }).attr('stroke-width', l => {
      const src = typeof l.source === 'string' ? l.source : l.source?.id;
      const tgt = typeof l.target === 'string' ? l.target : l.target?.id;
      return (criticalIds.has(src) || criticalIds.has(tgt)) ? 2.5 : 0.5;
    });
    state._nodeSelection.attr('opacity', d => pathNodeIds.has(d.id) ? 1 : 0.08);
    // Show labels on path nodes
    state._nodeSelection.each(function(d) {
      d3.select(this).select('.node-label')
        .attr('opacity', pathNodeIds.has(d.id) ? 1 : 0);
    });
  }

  toast(`Found ${criticalNodes.length} attack path(s) through ${pathNodeIds.size} nodes`, 'success');
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────
function renderTargetSelect() {
  const select = el('targetSelect');
  if (!select) return;
  select.innerHTML = '<option value="">— Select a completed scan target —</option>' +
    state.targets.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
}

function showLoading(show) {
  const container = el('graphContainer');
  if (!container) return;
  let loader = container.querySelector('.graph-loading');
  if (show) {
    if (!loader) {
      loader = document.createElement('div');
      loader.className = 'graph-loading';
      loader.innerHTML = '<span class="spinner"></span> Loading all phase results...';
      loader.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--text-secondary);display:flex;align-items:center;gap:8px;z-index:10;';
      container.style.position = 'relative';
      container.appendChild(loader);
    }
  } else if (loader) {
    loader.remove();
  }
}

function showEmptyState(msg) {
  const container = el('graphContainer');
  if (!container) return;
  let empty = el('graphEmpty') || container.querySelector('.graph-empty');
  if (!empty) {
    empty = document.createElement('div');
    empty.className = 'graph-empty';
    empty.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--text-secondary);text-align:center;';
    container.appendChild(empty);
  }
  empty.style.display = '';
  empty.innerHTML = `<p>${msg}</p>`;
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }

function hdrs() { return {}; }

async function apiGet(path) {
  const res = await fetch(`${API}${path}`, { headers: hdrs() });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

function esc(text) {
  const d = document.createElement('div');
  d.textContent = text || '';
  return d.innerHTML;
}

function truncate(str, len) {
  return (str || '').length > len ? str.slice(0, len) + '...' : (str || '');
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function animateNum(id, target) {
  const e = el(id);
  if (!e) return;
  const start = parseInt(e.textContent) || 0;
  if (start === target) return;
  const t0 = performance.now();
  (function tick(now) {
    const p = Math.min((now - t0) / 400, 1);
    e.textContent = Math.floor(start + (target - start) * p * (2 - p));
    if (p < 1) requestAnimationFrame(tick);
  })(performance.now());
}

function toast(msg, type = 'info') {
  const c = el('toastContainer');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function initSidebar() {
  const toggle = el('sidebarToggle');
  const sidebar = el('sidebar');
  const overlay = el('sidebarOverlay');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay?.classList.toggle('open');
    });
  }
  if (overlay) overlay.addEventListener('click', () => {
    sidebar?.classList.remove('open');
    overlay.classList.remove('open');
  });
}
