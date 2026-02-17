/**
 * ReconX Enterprise — Attack Graph Visualization v2.0
 * Wired to: GET /api/v1/assets/targets, /api/v1/assets/subdomains/{t},
 *           /api/v1/assets/ports/{t}, /api/v1/findings/{t}
 * Uses D3.js v7 force-directed graph
 */

const API = '/api/v1';

// Auto-bootstrap: fetch and store API key if none configured
async function ensureApiKey() {
  const stored = localStorage.getItem('reconx_api_key');
  if (stored && stored !== 'demo_key' && stored.length >= 32) return;
  try {
    const res = await fetch('/api/v1/bootstrap-key');
    if (res.ok) {
      const data = await res.json();
      if (data.key) {
        localStorage.setItem('reconx_api_key', data.key);
        console.log('Bootstrap API key auto-configured');
      }
    }
  } catch { /* ignore */ }
}

let state = {
  targets: [],
  selectedTarget: '',
  nodes: [],
  links: [],
  simulation: null,
  svg: null,
  g: null,
  zoom: null,
  showSubdomains: true,
  showPorts: true,
  showFindings: true,
  selectedNode: null,
  stats: { nodes: 0, edges: 0, attackPaths: 0, criticalAssets: 0 }
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  bindEvents();
  initGraph();
  loadTargets();
});

function bindEvents() {
  el('targetSelect')?.addEventListener('change', onTargetChange);
  el('showSubdomains')?.addEventListener('change', onOptionsChange);
  el('showPorts')?.addEventListener('change', onOptionsChange);
  el('showFindings')?.addEventListener('change', onOptionsChange);
  el('resetGraphBtn')?.addEventListener('click', resetZoom);
  el('exportSvgBtn')?.addEventListener('click', exportSVG);
  el('findPathsBtn')?.addEventListener('click', findAttackPaths);
  el('closeNodePanel')?.addEventListener('click', closeNodePanel);
  window.addEventListener('resize', debounce(resizeGraph, 250));
}

// ─── Data ─────────────────────────────────────────────────────────────────────
async function loadTargets() {
  try {
    const data = await apiGet('/assets/targets');
    state.targets = data?.targets || [];
    renderTargetSelect();
    if (state.targets.length > 0) {
      state.selectedTarget = state.targets[0];
      el('targetSelect').value = state.selectedTarget;
      loadGraphData();
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
    const results = await Promise.all([
      state.showSubdomains ? apiGet(`/assets/subdomains/${target}`).catch(() => ({ subdomains: [] })) : { subdomains: [] },
      state.showPorts ? apiGet(`/assets/ports/${target}`).catch(() => ({ ports: [] })) : { ports: [] },
      state.showFindings ? apiGet(`/findings/${target}`).catch(() => ({ findings: [] })) : { findings: [] }
    ]);

    buildGraph(
      results[0]?.subdomains || [],
      results[1]?.ports || [],
      results[2]?.findings || []
    );
  } catch (err) {
    console.error('Graph data load failed:', err);
    showEmptyState('Failed to load target data.');
  } finally {
    showLoading(false);
  }
}

function onTargetChange() {
  state.selectedTarget = el('targetSelect')?.value || '';
  if (state.selectedTarget) loadGraphData();
}

function onOptionsChange() {
  state.showSubdomains = el('showSubdomains')?.checked ?? true;
  state.showPorts = el('showPorts')?.checked ?? true;
  state.showFindings = el('showFindings')?.checked ?? true;
  if (state.selectedTarget) loadGraphData();
}

// ─── Graph Construction ───────────────────────────────────────────────────────
function buildGraph(subdomains, ports, findings) {
  const nodes = [];
  const links = [];
  const nodeMap = {};

  // Root target node
  const rootId = `target:${state.selectedTarget}`;
  nodes.push({ id: rootId, label: state.selectedTarget, type: 'target', size: 28, data: {} });
  nodeMap[rootId] = true;

  // Subdomain nodes
  subdomains.forEach(sub => {
    const host = typeof sub === 'string' ? sub : sub.subdomain || sub.host || sub.name;
    if (!host) return;
    const id = `sub:${host}`;
    if (nodeMap[id]) return;
    nodes.push({ id, label: host, type: 'subdomain', size: 14, data: sub });
    nodeMap[id] = true;
    links.push({ source: rootId, target: id, type: 'has_subdomain' });
  });

  // Port nodes (group by host)
  const portsByHost = {};
  ports.forEach(p => {
    const host = p.host || p.ip || state.selectedTarget;
    if (!portsByHost[host]) portsByHost[host] = [];
    portsByHost[host].push(p);
  });

  Object.entries(portsByHost).forEach(([host, hostPorts]) => {
    const parentId = nodeMap[`sub:${host}`] ? `sub:${host}` : rootId;
    hostPorts.forEach(p => {
      const port = p.port || p.portid;
      const id = `port:${host}:${port}`;
      if (nodeMap[id]) return;
      nodes.push({
        id, label: `${port}/${p.protocol || 'tcp'}`,
        type: 'port', size: 8,
        data: { ...p, host, service: p.service || p.name || '' }
      });
      nodeMap[id] = true;
      links.push({ source: parentId, target: id, type: 'open_port' });
    });
  });

  // Finding nodes
  let criticalCount = 0;
  findings.forEach((f, i) => {
    const severity = (f.severity || f.risk || 'info').toLowerCase();
    const host = f.host || f.url || state.selectedTarget;
    const id = `vuln:${i}:${f.name || 'finding'}`;

    nodes.push({
      id, label: f.name || f.title || `Finding ${i + 1}`,
      type: 'finding', size: severity === 'critical' ? 16 : severity === 'high' ? 13 : 10,
      severity, data: f
    });
    nodeMap[id] = true;

    // Link to host if possible
    const parentId = nodeMap[`sub:${host}`] ? `sub:${host}` : rootId;
    links.push({ source: parentId, target: id, type: 'vulnerability' });

    if (severity === 'critical') criticalCount++;
  });

  state.nodes = nodes;
  state.links = links;
  state.stats = {
    nodes: nodes.length,
    edges: links.length,
    attackPaths: findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
    criticalAssets: criticalCount
  };

  renderStats();
  renderGraph();
}

// ─── D3 Graph ─────────────────────────────────────────────────────────────────
function initGraph() {
  const container = el('graphContainer');
  if (!container) return;
  const width = container.clientWidth;
  const height = container.clientHeight || 600;

  state.svg = d3.select('#graphContainer')
    .append('svg')
    .attr('width', '100%')
    .attr('height', '100%')
    .attr('viewBox', `0 0 ${width} ${height}`);

  // Defs for arrow markers
  const defs = state.svg.append('defs');
  ['#3B82F6', '#06B6D4', '#F59E0B', '#EF4444'].forEach((color, i) => {
    defs.append('marker')
      .attr('id', `arrow-${i}`)
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

  const container = el('graphContainer');
  const width = container.clientWidth;
  const height = container.clientHeight || 600;

  const colorMap = {
    target: '#F59E0B',
    subdomain: '#3B82F6',
    port: '#06B6D4',
    finding: '#EF4444'
  };

  const findingColor = (d) => {
    if (d.type !== 'finding') return colorMap[d.type] || '#6B7280';
    const sev = d.severity || 'info';
    return sev === 'critical' ? '#DC2626' : sev === 'high' ? '#F97316' :
           sev === 'medium' ? '#F59E0B' : sev === 'low' ? '#3B82F6' : '#6B7280';
  };

  // Simulation
  if (state.simulation) state.simulation.stop();

  state.simulation = d3.forceSimulation(state.nodes)
    .force('link', d3.forceLink(state.links).id(d => d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => d.size + 5));

  // Links
  const link = state.g.append('g')
    .selectAll('line')
    .data(state.links)
    .join('line')
    .attr('stroke', '#334155')
    .attr('stroke-width', 1)
    .attr('stroke-opacity', 0.6);

  // Nodes
  const node = state.g.append('g')
    .selectAll('g')
    .data(state.nodes)
    .join('g')
    .attr('class', 'node-group')
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', dragStarted)
      .on('drag', dragged)
      .on('end', dragEnded)
    )
    .on('click', (event, d) => selectNode(d));

  // Node circles
  node.append('circle')
    .attr('r', d => d.size)
    .attr('fill', d => findingColor(d))
    .attr('stroke', d => d3.color(findingColor(d)).brighter(0.5))
    .attr('stroke-width', 1.5)
    .attr('opacity', 0.9);

  // Node labels
  node.append('text')
    .text(d => truncate(d.label, 20))
    .attr('x', d => d.size + 5)
    .attr('y', 4)
    .attr('fill', '#94A3B8')
    .attr('font-size', d => d.type === 'target' ? '12px' : '9px')
    .attr('font-family', 'monospace');

  // Simulation tick
  state.simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Clear empty state
  if (state.nodes.length > 0) {
    const empty = container.querySelector('.graph-empty');
    if (empty) empty.style.display = 'none';
  }
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

  const propsDiv = el('nodePanelBody');
  let html = '';

  if (d.type === 'target') {
    html = `<div class="prop-row"><span class="prop-key">Type</span><span class="prop-val">Target</span></div>
            <div class="prop-row"><span class="prop-key">Domain</span><span class="prop-val">${esc(d.label)}</span></div>`;
  } else if (d.type === 'subdomain') {
    const data = d.data || {};
    html = `
      <div class="prop-row"><span class="prop-key">Host</span><span class="prop-val">${esc(d.label)}</span></div>
      ${data.ip ? `<div class="prop-row"><span class="prop-key">IP</span><span class="prop-val">${esc(data.ip)}</span></div>` : ''}
      ${data.alive !== undefined ? `<div class="prop-row"><span class="prop-key">Status</span><span class="prop-val">${data.alive ? 'Alive' : 'Down'}</span></div>` : ''}
    `;
  } else if (d.type === 'port') {
    const data = d.data || {};
    html = `
      <div class="prop-row"><span class="prop-key">Port</span><span class="prop-val">${esc(d.label)}</span></div>
      <div class="prop-row"><span class="prop-key">Host</span><span class="prop-val">${esc(data.host || '')}</span></div>
      ${data.service ? `<div class="prop-row"><span class="prop-key">Service</span><span class="prop-val">${esc(data.service)}</span></div>` : ''}
      ${data.version ? `<div class="prop-row"><span class="prop-key">Version</span><span class="prop-val">${esc(data.version)}</span></div>` : ''}
    `;
  } else if (d.type === 'finding') {
    const data = d.data || {};
    html = `
      <div class="prop-row"><span class="prop-key">Severity</span><span class="prop-val"><span class="badge badge-${d.severity || 'info'}">${(d.severity || 'info').toUpperCase()}</span></span></div>
      <div class="prop-row"><span class="prop-key">Name</span><span class="prop-val">${esc(data.name || data.title || '')}</span></div>
      ${data.cve ? `<div class="prop-row"><span class="prop-key">CVE</span><span class="prop-val">${esc(data.cve)}</span></div>` : ''}
      ${data.host ? `<div class="prop-row"><span class="prop-key">Host</span><span class="prop-val">${esc(data.host)}</span></div>` : ''}
      ${data.tool ? `<div class="prop-row"><span class="prop-key">Tool</span><span class="prop-val">${esc(data.tool)}</span></div>` : ''}
      ${data.description ? `<div class="prop-row"><span class="prop-key">Description</span><span class="prop-val" style="white-space:pre-wrap;font-size:0.75rem;">${esc(data.description)}</span></div>` : ''}
    `;
  }

  propsDiv.innerHTML = html;
  panel.classList.remove('hidden');
}

function closeNodePanel() {
  const panel = el('nodePanel');
  if (panel) panel.classList.add('hidden');
  state.selectedNode = null;
}

// ─── Zoom Controls ────────────────────────────────────────────────────────────
function resetZoom() {
  if (state.svg && state.zoom) {
    state.svg.transition().duration(500).call(state.zoom.transform, d3.zoomIdentity);
  }
}

function resizeGraph() {
  const container = el('graphContainer');
  if (!container || !state.svg) return;
  const w = container.clientWidth;
  const h = container.clientHeight || 600;
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
  a.download = `reconx-graph-${state.selectedTarget || 'export'}.svg`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Graph exported as SVG', 'success');
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────
function renderTargetSelect() {
  const select = el('targetSelect');
  if (!select) return;
  select.innerHTML = '<option value="">Select target...</option>' +
    state.targets.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
}

function renderStats() {
  animateNum('nodeCount', state.stats.nodes);
  animateNum('edgeCount', state.stats.edges);
  animateNum('pathCount', state.stats.attackPaths);
  animateNum('criticalAssets', state.stats.criticalAssets);
}

function showLoading(show) {
  const container = el('graphContainer');
  if (!container) return;
  let loader = container.querySelector('.graph-loading');
  if (show) {
    if (!loader) {
      loader = document.createElement('div');
      loader.className = 'graph-loading';
      loader.innerHTML = '<span class="spinner"></span> Loading graph data...';
      loader.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--text-secondary);display:flex;align-items:center;gap:8px;';
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
  const empty = container.querySelector('.graph-empty') || document.createElement('div');
  empty.className = 'graph-empty';
  empty.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--text-secondary);text-align:center;';
  empty.innerHTML = `<p>${msg}</p>`;
  if (!container.contains(empty)) container.appendChild(empty);
}

// ─── Attack Paths ──────────────────────────────────────────────────────────────
function findAttackPaths() {
  if (!state.nodes || state.nodes.length === 0) {
    toast('Load a graph first before finding attack paths', 'warning');
    return;
  }
  // Highlight critical/high severity finding nodes and their connections
  const criticalNodes = state.nodes.filter(n => n.type === 'finding' && (n.severity === 'critical' || n.severity === 'high'));
  if (criticalNodes.length === 0) {
    toast('No critical or high severity findings found', 'info');
    return;
  }
  const criticalIds = new Set(criticalNodes.map(n => n.id));
  // Find all links that connect to critical nodes
  const pathLinks = state.links.filter(l => {
    const src = typeof l.source === 'string' ? l.source : l.source.id;
    const tgt = typeof l.target === 'string' ? l.target : l.target.id;
    return criticalIds.has(src) || criticalIds.has(tgt);
  });
  const pathNodeIds = new Set();
  pathLinks.forEach(l => {
    pathNodeIds.add(typeof l.source === 'string' ? l.source : l.source.id);
    pathNodeIds.add(typeof l.target === 'string' ? l.target : l.target.id);
  });

  // Visual highlight
  if (state.g) {
    state.g.selectAll('line').attr('opacity', l => {
      const src = typeof l.source === 'string' ? l.source : l.source.id;
      const tgt = typeof l.target === 'string' ? l.target : l.target.id;
      return (criticalIds.has(src) || criticalIds.has(tgt)) ? 1 : 0.1;
    });
    state.g.selectAll('g.node-group').attr('opacity', d => pathNodeIds.has(d.id) ? 1 : 0.15);
  }

  toast(`Found ${criticalNodes.length} attack path(s) through ${pathNodeIds.size} nodes`, 'success');
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function hdrs() {
  const key = localStorage.getItem('reconx_api_key') || '';
  if (!key) console.warn('reconx_api_key not set; call ensureApiKey() first');
  return { 'X-API-Key': key };
}

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
