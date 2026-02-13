/**
 * ReconX Enterprise - Graph Visualization v2.0
 * D3.js force-directed graph for attack surface analysis
 */

const API_BASE = window.location.origin;
const API_V1 = `${API_BASE}/api/v1`;

// HTML escape utility — prevents XSS when inserting data into innerHTML
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// State management
const state = {
  graphData: { nodes: [], links: [] },
  filteredData: { nodes: [], links: [] },
  currentScanId: null,
  simulation: null,
  svg: null,
  g: null,
  selectedNode: null,
  attackPaths: [],
  nodeElements: null,
  linkElements: null,
  labelElements: null
};

// Color schemes
const colors = {
  domain: '#60A5FA',      // Blue
  subdomain: '#60A5FA',   // Blue
  ip: '#34D399',          // Green
  service: '#F59E0B',     // Orange
  vulnerability: '#DC2626', // Red
  asset: '#A78BFA'        // Purple
};

const riskColors = {
  critical: '#DC2626',
  high: '#F97316',
  medium: '#FBBF24',
  low: '#3B82F6'
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
 initializeSVG();
  loadScans();
  checkURLParameters();
});

function checkURLParameters() {
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get('id');
  if (scanId) {
    document.getElementById('scanSelect').value = scanId;
    state.currentScanId = parseInt(scanId);
    loadGraph();
  }
}

function initializeSVG() {
  const container = document.getElementById('graphContainer');
  const width = container.clientWidth;
  const height = container.clientHeight;

  // Create SVG
  state.svg = d3.select('#graphContainer')
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .style('background', 'var(--bg-dark)');

  // Add zoom behavior
  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on('zoom', (event) => {
      state.g.attr('transform', event.transform);
    });

  state.svg.call(zoom);

  // Main group for zoom/pan
  state.g = state.svg.append('g');

  // Initialize force simulation
  state.simulation = d3.forceSimulation()
    .force('link', d3.forceLink().id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(30));
}

// ============================================================================
// DATA LOADING
// ============================================================================
async function loadScans() {
  try {
    const response = await fetch(`${API_V1}/scans/?per_page=100`, {
      headers: getHeaders()
    });

    if (!response.ok) return;

    const data = await response.json();
    const scanSelect = document.getElementById('scanSelect');
    
    data.items?.forEach(scan => {
      const option = document.createElement('option');
      option.value = scan.id;
      option.textContent = `#${scan.id} - ${scan.target} (${scan.status})`;
      scanSelect.appendChild(option);
    });
  } catch (error) {
    console.error('Failed to load scans:', error);
  }
}

async function loadGraph() {
  const scanId = document.getElementById('scanSelect').value;
  if (!scanId) return;

  state.currentScanId = parseInt(scanId);
  showLoading();

  try {
    const response = await fetch(`${API_V1}/intelligence/graph/${scanId}`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error('Failed to load graph data');

    const data = await response.json();
    state.graphData = transformGraphData(data);
    state.filteredData = JSON.parse(JSON.stringify(state.graphData)); // Deep copy

    updateStats();
    filterGraph(); // Apply initial filters
    renderGraph();
    hideLoading();

  } catch (error) {
    console.error('Failed to load graph:', error);
    showError('Failed to load graph data. The scan may not have intelligence data yet.');
  }
}

function transformGraphData(apiData) {
  // Transform API response to D3-compatible format
  const nodes = [];
  const links = [];
  const nodeMap = new Map();

  // Process nodes from API
  if (apiData.nodes) {
    apiData.nodes.forEach((node, index) => {
      const nodeData = {
        id: node.id || `node_${index}`,
        label: node.label || node.name || node.id,
        type: node.type || 'asset',
        risk_score: node.risk_score || 0,
        metadata: node.metadata || {}
      };
      nodes.push(nodeData);
      nodeMap.set(nodeData.id, nodeData);
    });
  }

  // Process edges/links from API
  if (apiData.edges) {
    apiData.edges.forEach(edge => {
      if (nodeMap.has(edge.source) && nodeMap.has(edge.target)) {
        links.push({
          source: edge.source,
          target: edge.target,
          type: edge.type || 'connected',
          weight: edge.weight || 1
        });
      }
    });
  }

  // If no data from API, generate sample data for demonstration
  if (nodes.length === 0) {
    return generateSampleGraph();
  }

  return { nodes, links };
}

function generateSampleGraph() {
  // Generate sample graph for demonstration
  const nodes = [
    { id: 'root', label: 'example.com', type: 'domain', risk_score: 7.5 },
    { id: 'sub1', label: 'www.example.com', type: 'subdomain', risk_score: 6.2 },
    { id: 'sub2', label: 'api.example.com', type: 'subdomain', risk_score: 8.1 },
    { id: 'sub3', label: 'admin.example.com', type: 'subdomain', risk_score: 9.2 },
    { id: 'ip1', label: '192.168.1.100', type: 'ip', risk_score: 7.0 },
    { id: 'ip2', label: '192.168.1.101', type: 'ip', risk_score: 8.5 },
    { id: 'svc1', label: 'HTTP:80', type: 'service', risk_score: 5.0 },
    { id: 'svc2', label: 'HTTPS:443', type: 'service', risk_score: 6.5 },
    { id: 'svc3', label: 'SSH:22', type: 'service', risk_score: 7.8 },
    { id: 'vuln1', label: 'CVE-2023-1234', type: 'vulnerability', risk_score: 9.8 },
    { id: 'vuln2', label: 'CVE-2023-5678', type: 'vulnerability', risk_score: 8.2 },
    { id: 'vuln3', label: 'Weak SSL/TLS', type: 'vulnerability', risk_score: 7.5 }
  ];

  const links = [
    { source: 'root', target: 'sub1', type: 'subdomain_of', weight: 1 },
    { source: 'root', target: 'sub2', type: 'subdomain_of', weight: 1 },
    { source: 'root', target: 'sub3', type: 'subdomain_of', weight: 1 },
    { source: 'sub1', target: 'ip1', type: 'resolves_to', weight: 1 },
    { source: 'sub2', target: 'ip2', type: 'resolves_to', weight: 1 },
    { source: 'sub3', target: 'ip2', type: 'resolves_to', weight: 1 },
    { source: 'ip1', target: 'svc1', type: 'hosts', weight: 1 },
    { source: 'ip1', target: 'svc2', type: 'hosts', weight: 1 },
    { source: 'ip2', target: 'svc2', type: 'hosts', weight: 1 },
    { source: 'ip2', target: 'svc3', type: 'hosts', weight: 1 },
    { source: 'svc2', target: 'vuln1', type: 'has_vulnerability', weight: 2 },
    { source: 'svc3', target: 'vuln2', type: 'has_vulnerability', weight: 2 },
    { source: 'svc2', target: 'vuln3', type: 'has_vulnerability', weight: 1 }
  ];

  return { nodes, links };
}

// ============================================================================
// FILTERING
// ============================================================================
function filterGraph() {
  const nodeTypes = Array.from(document.getElementById('nodeTypeFilter').selectedOptions).map(o => o.value);
  const riskLevels = Array.from(document.getElementById('riskFilter').selectedOptions).map(o => o.value);

  // Filter nodes
  state.filteredData.nodes = state.graphData.nodes.filter(node => {
    // Type filter
    if (!nodeTypes.includes(node.type)) return false;

    // Risk filter
    const risk = getRiskLevel(node.risk_score);
    if (!riskLevels.includes(risk)) return false;

    return true;
  });

  // Get filtered node IDs
  const nodeIds = new Set(state.filteredData.nodes.map(n => n.id));

  // Filter links (only keep links where both nodes are in filtered set)
  state.filteredData.links = state.graphData.links.filter(link => {
    const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
    const targetId = typeof link.target === 'object' ? link.target.id : link.target;
    return nodeIds.has(sourceId) && nodeIds.has(targetId);
  });

  updateStats();
  renderGraph();
}

function getRiskLevel(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

// ============================================================================
// GRAPH RENDERING
// ============================================================================
function renderGraph() {
  // Clear existing elements
  state.g.selectAll('*').remove();

  if (state.filteredData.nodes.length === 0) {
    showError('No nodes match the current filters');
    return;
  }

  // Create links
  state.linkElements = state.g.append('g')
    .attr('class', 'links')
    .selectAll('line')
    .data(state.filteredData.links)
    .enter()
    .append('line')
    .attr('stroke', '#475569')
    .attr('stroke-opacity', 0.6)
    .attr('stroke-width', d => Math.sqrt(d.weight) * 2);

  // Create nodes
  state.nodeElements = state.g.append('g')
    .attr('class', 'nodes')
    .selectAll('circle')
    .data(state.filteredData.nodes)
    .enter()
    .append('circle')
    .attr('r', d => 10 + (d.risk_score / 10) * 10) // Size based on risk
    .attr('fill', d => getNodeColor(d))
    .attr('stroke', '#fff')
    .attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .call(drag(state.simulation))
    .on('click', (event, d) => showNodeDetails(d))
    .on('mouseover', (event, d) => highlightNode(d))
    .on('mouseout', () => unhighlightNode());

  // Create labels
  state.labelElements = state.g.append('g')
    .attr('class', 'labels')
    .selectAll('text')
    .data(state.filteredData.nodes)
    .enter()
    .append('text')
    .text(d => d.label)
    .attr('font-size', 10)
    .attr('fill', '#CBD5E1')
    .attr('text-anchor', 'middle')
    .attr('dy', -15);

  // Update simulation
  state.simulation.nodes(state.filteredData.nodes);
  state.simulation.force('link').links(state.filteredData.links);
  state.simulation.alpha(1).restart();

  // Tick function
  state.simulation.on('tick', () => {
    state.linkElements
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    state.nodeElements
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);

    state.labelElements
      .attr('x', d => d.x)
      .attr('y', d => d.y);
  });
}

function getNodeColor(node) {
  if (colors[node.type]) {
    return colors[node.type];
  }
  
  // Fallback to risk-based coloring
  const risk = getRiskLevel(node.risk_score);
  return riskColors[risk];
}

// ============================================================================
// INTERACTIONS
// ============================================================================
function drag(simulation) {
  function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }

  return d3.drag()
    .on('start', dragstarted)
    .on('drag', dragged)
    .on('end', dragended);
}

function highlightNode(node) {
  // Dim all nodes and links
  state.nodeElements.style('opacity', n => n === node ? 1 : 0.3);
  state.linkElements.style('opacity', l => {
    const source = l.source.id || l.source;
    const target = l.target.id || l.target;
    return (source === node.id || target === node.id) ? 1 : 0.1;
  });
}

function unhighlightNode() {
  state.nodeElements.style('opacity', 1);
  state.linkElements.style('opacity', 0.6);
}

function showNodeDetails(node) {
  state.selectedNode = node;
  const panel = document.getElementById('nodeDetailsPanel');
  const body = document.getElementById('nodeDetailsBody');

  document.getElementById('nodeDetailsTitle').textContent = node.label;

  const risk = getRiskLevel(node.risk_score);
  
  body.innerHTML = `
    <div style="margin-bottom: var(--spacing-md);">
      <span class="badge badge-${escapeHtml(risk)}">${escapeHtml(risk).toUpperCase()}</span>
      <span class="badge badge-info">${escapeHtml(node.type).toUpperCase()}</span>
    </div>

    <div style="margin-bottom: var(--spacing-md);">
      <div class="text-muted" style="font-size: 0.875rem;">Risk Score</div>
      <div style="font-size: 2rem; font-weight: bold; color: ${riskColors[risk]};">
        ${node.risk_score.toFixed(1)}
      </div>
    </div>

    <div style="margin-bottom: var(--spacing-md);">
      <h4 style="font-size: 0.875rem; margin-bottom: var(--spacing-sm);">Connections</h4>
      <div>${getNodeConnections(node)}</div>
    </div>

    ${node.metadata ? `
      <div style="margin-bottom: var(--spacing-md);">
        <h4 style="font-size: 0.875rem; margin-bottom: var(--spacing-sm);">Metadata</h4>
        <pre style="background: var(--bg-elevated); padding: var(--spacing-sm); border-radius: var(--radius-sm); font-size: 0.75rem; overflow-x: auto;">${escapeHtml(JSON.stringify(node.metadata, null, 2))}</pre>
      </div>
    ` : ''}

    <div class="flex gap-2">
      <button class="btn btn-primary btn-sm" onclick="analyzeNode()">Analyze</button>
      <button class="btn btn-secondary btn-sm" onclick="findPathsFrom()">Find Paths</button>
    </div>
  `;

  panel.classList.remove('hidden');
}

function getNodeConnections(node) {
  const incoming = state.filteredData.links.filter(l => {
    const target = l.target.id || l.target;
    return target === node.id;
  });

  const outgoing = state.filteredData.links.filter(l => {
    const source = l.source.id || l.source;
    return source === node.id;
  });

  return `
    <div class="text-muted" style="font-size: 0.875rem;">
      Incoming: <strong>${incoming.length}</strong><br>
      Outgoing: <strong>${outgoing.length}</strong><br>
      Total: <strong>${incoming.length + outgoing.length}</strong>
    </div>
  `;
}

function closeNodeDetails() {
  document.getElementById('nodeDetailsPanel').classList.add('hidden');
  state.selectedNode = null;
}

// ============================================================================
// ACTIONS
// ============================================================================
async function findAttackPaths() {
  if (!state.currentScanId) {
    alert('Please select a scan first');
    return;
  }

  try {
    const response = await fetch(`${API_V1}/intelligence/attack-paths/${state.currentScanId}`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error('Failed to find attack paths');

    const data = await response.json();
    state.attackPaths = data.paths || [];

    document.getElementById('pathCount').textContent = state.attackPaths.length;
    
    if (state.attackPaths.length > 0) {
      highlightAttackPaths();
      alert(`Found ${state.attackPaths.length} potential attack path(s)`);
    } else {
      alert('No attack paths found');
    }
  } catch (error) {
    console.error('Failed to find attack paths:', error);
    alert('Failed to analyze attack paths');
  }
}

function highlightAttackPaths() {
  if (!state.attackPaths || state.attackPaths.length === 0) return;

  // Get all nodes in attack paths
  const pathNodes = new Set();
  state.attackPaths.forEach(path => {
    path.forEach(nodeId => pathNodes.add(nodeId));
  });

  // Highlight nodes
  state.nodeElements
    .attr('stroke', d => pathNodes.has(d.id) ? '#EF4444' : '#fff')
    .attr('stroke-width', d => pathNodes.has(d.id) ? 4 : 2);
}

function analyzeNode() {
  if (!state.selectedNode) return;
  alert(`Analyzing ${state.selectedNode.label}...\n\nThis would trigger deep analysis of the selected node.`);
}

function findPathsFrom() {
  if (!state.selectedNode) return;
  alert(`Finding paths from ${state.selectedNode.label}...\n\nThis would find all paths originating from this node.`);
}

function resetGraph() {
  // Reset zoom
  state.svg.transition().duration(750).call(
    d3.zoom().transform,
    d3.zoomIdentity
  );

  // Restart simulation
  state.simulation.alpha(1).restart();
}

function exportGraph(format) {
  if (format === 'json') {
    const data = JSON.stringify(state.filteredData, null, 2);
    downloadFile(data, `graph_${state.currentScanId}.json`, 'application/json');
  } else if (format === 'svg') {
    const svgData = state.svg.node().outerHTML;
    downloadFile(svgData, `graph_${state.currentScanId}.svg`, 'image/svg+xml');
  }
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================================================
// TOGGLES
// ============================================================================
function toggleLabels() {
  const show = document.getElementById('showLabels').checked;
  state.labelElements?.style('display', show ? 'block' : 'none');
}

function toggleEdges() {
  const show = document.getElementById('showEdges').checked;
  state.linkElements?.style('display', show ? 'block' : 'none');
}

function togglePathHighlight() {
  const highlight = document.getElementById('highlightPaths').checked;
  if (highlight && state.attackPaths.length > 0) {
    highlightAttackPaths();
  } else {
    state.nodeElements?.attr('stroke', '#fff').attr('stroke-width', 2);
  }
}

// ============================================================================
// STATS
// ============================================================================
function updateStats() {
  document.getElementById('nodeCount').textContent = state.filteredData.nodes.length;
  document.getElementById('edgeCount').textContent = state.filteredData.links.length;
  
  const criticalNodes = state.filteredData.nodes.filter(n => n.risk_score >= 9).length;
  document.getElementById('criticalAssets').textContent = criticalNodes;
}

// ============================================================================
// UI HELPERS
// ============================================================================
function showLoading() {
  const container = document.getElementById('graphContainer');
  container.innerHTML = '<div class="empty-state" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);"><div class="spinner"></div><p>Loading graph...</p></div>';
  initializeSVG();
}

function hideLoading() {
  // Loading automatically cleared when SVG is rendered
}

function showError(message) {
  const container = document.getElementById('graphContainer');
  const emptyState = container.querySelector('.empty-state');
  if (emptyState) {
    emptyState.innerHTML = `<p class="text-danger">${escapeHtml(message)}</p>`;
  }
}

// ============================================================================
// UTILITIES
// ============================================================================
function getHeaders() {
  const apiKey = localStorage.getItem('reconx_api_key') || 'demo_key';
  return {
    'X-API-Key': apiKey
  };
}
