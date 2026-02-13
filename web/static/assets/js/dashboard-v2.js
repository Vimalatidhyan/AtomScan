/**
 * ReconX Enterprise - Dashboard v2.0
 * Production-ready dashboard with KPI cards, real-time updates, and modern UI
 */

const API_BASE = window.location.origin;
const API_V1 = `${API_BASE}/api/v1`;

// State management
const state = {
  targets: [],
  scans: [],
  stats: {
    critical: 0,
    high: 0,
    assets: 0,
    activeScans: 0
  },
  refreshInterval: null
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initializeEventListeners();
  loadDashboardData();
  startAutoRefresh();
});

function initializeEventListeners() {
  document.getElementById('startScan')?.addEventListener('click', handleStartScan);
  document.getElementById('refreshTargets')?.addEventListener('click', () => loadTargets());
  document.getElementById('viewAllScans')?.addEventListener('click', () => {
    window.location.href = '/scan_viewer.html';
  });
}

function startAutoRefresh() {
  // Refresh dashboard every 30 seconds
  state.refreshInterval = setInterval(() => {
    loadDashboardData(false); // Silent refresh
  }, 30000);
}

// ============================================================================
// DATA LOADING
// ============================================================================
async function loadDashboardData(showLoading = true) {
  try {
    await Promise.all([
      loadStats(),
      loadTargets(showLoading),
      loadRecentScans(showLoading)
    ]);
  } catch (error) {
    console.error('Failed to load dashboard data:', error);
    showError('Failed to load dashboard data. Please refresh the page.');
  }
}

async function loadStats() {
  try {
    // Load findings by severity
    const response = await fetch(`${API_V1}/findings/by-severity`, {
      headers: getHeaders()
    });
    
    if (response.ok) {
      const data = await response.json();
      state.stats.critical = data.critical || 0;
      state.stats.high = data.high || 0;
      updateKPICards();
    }

    // Load asset count
    const assetsResponse = await fetch(`${API_V1}/assets/subdomains?per_page=1`, {
      headers: getHeaders()
    });
    
    if (assetsResponse.ok) {
      const assetsData = await assetsResponse.json();
      state.stats.assets = assetsData.total || 0;
      updateKPICards();
    }

    // Load active scans
    const scansResponse = await fetch(`${API_V1}/scans/?per_page=100`, {
      headers: getHeaders()
    });
    
    if (scansResponse.ok) {
      const scansData = await scansResponse.json();
      state.stats.activeScans = scansData.items?.filter(s => s.status === 'running').length || 0;
      updateKPICards();
    }
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

async function loadTargets(showLoading = true) {
  const loadingEl = document.getElementById('targetsLoading');
  const listEl = document.getElementById('targetsList');
  
  if (showLoading) {
    loadingEl?.classList.remove('hidden');
    listEl?.classList.add('hidden');
  }

  try {
    const response = await fetch(`${API_V1}/scans/`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    state.targets = getUniqueTargets(data.items || []);
    renderTargets();
    
    loadingEl?.classList.add('hidden');
    listEl?.classList.remove('hidden');
  } catch (error) {
    console.error('Failed to load targets:', error);
    loadingEl.innerHTML = `<div class="empty-state"><p style="color: var(--danger);">Failed to load targets</p></div>`;
  }
}

async function loadRecentScans(showLoading = true) {
  const loadingEl = document.getElementById('scansLoading');
  const listEl = document.getElementById('scansList');

  if (showLoading) {
    loadingEl?.classList.remove('hidden');
    listEl?.classList.add('hidden');
  }

  try {
    const response = await fetch(`${API_V1}/scans/?per_page=10`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    state.scans = data.items || [];
    renderScans();
    
    loadingEl?.classList.add('hidden');
    listEl?.classList.remove('hidden');
  } catch (error) {
    console.error('Failed to load scans:', error);
    loadingEl.innerHTML = `<div class="empty-state"><p style="color: var(--danger);">Failed to load scans</p></div>`;
  }
}

// ============================================================================
// RENDERING
// ============================================================================
function updateKPICards() {
  const criticalEl = document.getElementById('criticalCount');
  const highEl = document.getElementById('highCount');
  const assetEl = document.getElementById('assetCount');
  const activeScanEl = document.getElementById('activeScanCount');

  if (criticalEl) animateValue(criticalEl, parseInt(criticalEl.textContent) || 0, state.stats.critical, 500);
  if (highEl) animateValue(highEl, parseInt(highEl.textContent) || 0, state.stats.high, 500);
  if (assetEl) animateValue(assetEl, parseInt(assetEl.textContent) || 0, state.stats.assets, 500);
  if (activeScanEl) animateValue(activeScanEl, parseInt(activeScanEl.textContent) || 0, state.stats.activeScans, 500);
}

function animateValue(el, start, end, duration) {
  const startTime = performance.now();
  const diff = end - start;

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const current = Math.floor(start + diff * easeOutQuad(progress));
    el.textContent = current.toLocaleString();

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

function easeOutQuad(t) {
  return t * (2 - t);
}

function renderTargets() {
  const listEl = document.getElementById('targetsList');
  if (!listEl || state.targets.length === 0) {
    listEl.innerHTML = '<div class="empty-state"><p>No targets found. Start a scan to begin monitoring.</p></div>';
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'kpi-grid';
  grid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(200px, 1fr))';

  state.targets.forEach(target => {
    const card = document.createElement('div');
    card.className = 'kpi-card';
    card.innerHTML = `
      <div class="kpi-header">
        <span class="kpi-label">${escapeHtml(target.name)}</span>
      </div>
      <div class="kpi-value" style="font-size: 1.5rem;">${target.scanCount}</div>
      <div class="kpi-change">
        <span class="text-muted">${target.scanCount === 1 ? 'scan' : 'scans'}</span>
      </div>
    `;
    grid.appendChild(card);
  });

  listEl.innerHTML = '';
  listEl.appendChild(grid);
}

function renderScans() {
  const tbody = document.getElementById('scansTableBody');
  if (!tbody) return;

  if (state.scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center" style="padding: 2rem;">
          <p class="text-muted">No scans found. Start your first scan above.</p>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.scans.map(scan => {
    const duration = scan.completed_at 
      ? formatDuration(new Date(scan.started_at), new Date(scan.completed_at))
      : formatDuration(new Date(scan.started_at), new Date());
    
    const findingsCount = (scan.findings_count || 0);
    
    return `
      <tr>
        <td><span class="font-mono">#${scan.id}</span></td>
        <td><strong>${escapeHtml(scan.target)}</strong></td>
        <td><span class="status-badge status-${scan.status}">${scan.status}</span></td>
        <td><span class="text-muted">${formatDateTime(scan.started_at)}</span></td>
        <td><span class="font-mono">${duration}</span></td>
        <td>
          ${findingsCount > 0 
            ? `<span class="badge badge-${getSeverityClass(findingsCount)}">${findingsCount}</span>`
            : `<span class="text-muted">—</span>`
          }
        </td>
        <td class="table-actions">
          <button class="btn btn-sm btn-ghost" onclick="viewScan(${scan.id})">View</button>
        </td>
      </tr>
    `;
  }).join('');
}

// ============================================================================
// ACTIONS
// ============================================================================
async function handleStartScan() {
  const targetInput = document.getElementById('target');
  const phasesInput = document.getElementById('phases');
  const testModeCheck = document.getElementById('testMode');
  const msgEl = document.getElementById('scanMsg');
  const startBtn = document.getElementById('startScan');

  const target = targetInput?.value.trim();
  const phases = phasesInput?.value.trim();
  const testMode = testModeCheck?.checked;

  if (!target) {
    showMessage(msgEl, 'Please enter a target domain', 'error');
    return;
  }

  startBtn.disabled = true;
  startBtn.innerHTML = '<span class="loading-spinner"></span><span>Starting...</span>';

  try {
    const response = await fetch(`${API_V1}/scans/`, {
      method: 'POST',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        target,
        phases: phases || '1,2,3,4',
        test_mode: testMode
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to start scan');
    }

    const data = await response.json();
    showMessage(msgEl, `Scan started successfully! ID: ${data.run_id}`, 'success');
    
    // Refresh data
    setTimeout(() => {
      loadDashboardData(false);
    }, 1000);

    // Redirect to scan viewer
    setTimeout(() => {
      window.location.href = `/scan_viewer.html?id=${data.run_id}`;
    }, 1500);

  } catch (error) {
    console.error('Scan start failed:', error);
    showMessage(msgEl, error.message, 'error');
  } finally {
    startBtn.disabled = false;
    startBtn.innerHTML = '<span>Start Scan</span>';
  }
}

function viewScan(scanId) {
  window.location.href = `/scan_viewer.html?id=${scanId}`;
}

// ============================================================================
// UTILITIES
// ============================================================================
function getHeaders() {
  // In production, retrieve API key from secure storage
  const apiKey = localStorage.getItem('reconx_api_key') || 'demo_key';
  return {
    'X-API-Key': apiKey
  };
}

function getUniqueTargets(scans) {
  const targetMap = new Map();
  
  scans.forEach(scan => {
    const target = scan.target;
    if (targetMap.has(target)) {
      targetMap.get(target).scanCount++;
    } else {
      targetMap.set(target, {
        name: target,
        scanCount: 1
      });
    }
  });

  return Array.from(targetMap.values())
    .sort((a, b) => b.scanCount - a.scanCount)
    .slice(0, 6); // Top 6 targets
}

function showMessage(el, message, type = 'info') {
  if (!el) return;
  
  el.textContent = message;
  el.className = '';
  el.classList.add('badge');
  
  if (type === 'error') {
    el.style.background = 'rgba(239, 68, 68, 0.15)';
    el.style.color = 'var(--danger)';
  } else if (type === 'success') {
    el.style.background = 'rgba(16, 185, 129, 0.15)';
    el.style.color = 'var(--success)';
  } else {
    el.style.background = 'rgba(59, 130, 246, 0.15)';
    el.style.color = 'var(--primary)';
  }
  
  el.style.padding = '0.75rem';
  el.style.borderRadius = '0.5rem';
  el.style.display = 'block';
  el.classList.remove('hidden');

  if (type === 'success') {
    setTimeout(() => {
      el.classList.add('hidden');
    }, 5000);
  }
}

function showError(message) {
  console.error(message);
  // Could implement toast notifications here
}

function formatDateTime(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  const now = new Date();
  const diff = now - date;
  
  // Less than 1 minute
  if (diff < 60000) return 'Just now';
  // Less than 1 hour
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  // Less than 24 hours
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  // More than 24 hours
  return date.toLocaleDateString();
}

function formatDuration(start, end) {
  const diff = end - start;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function getSeverityClass(count) {
  if (count >= 10) return 'critical';
  if (count >= 5) return 'high';
  if (count >= 1) return 'medium';
  return 'low';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  if (state.refreshInterval) {
    clearInterval(state.refreshInterval);
  }
});
