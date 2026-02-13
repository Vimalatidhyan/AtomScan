/**
 * ReconX Enterprise - Scan Monitor v2.0
 * Real-time scan monitoring with SSE streaming, phase tracking, and live stats
 */

const API_BASE = window.location.origin;
const API_V1 = `${API_BASE}/api/v1`;

// State management
const state = {
  currentScanId: null,
  eventSource: null,
  startTime: null,
  updateInterval: null,
  logs: [],
  scanData: null,
  stats: {
    subdomains: 0,
    ports: 0,
    services: 0,
    vulnerabilities: 0
  }
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initializeEventListeners();
  loadAvailableScans();
  checkURLParameters();
});

function initializeEventListeners() {
  document.getElementById('loadScanBtn')?.addEventListener('click', loadSelectedScan);
  document.getElementById('scanSelect')?.addEventListener('change', handleScanSelectChange);
  document.getElementById('pauseScanBtn')?.addEventListener('click', () => handleScanAction('pause'));
  document.getElementById('stopScanBtn')?.addEventListener('click', () => handleScanAction('stop'));
  document.getElementById('clearLogsBtn')?.addEventListener('click', clearLogs);
  document.getElementById('exportLogsBtn')?.addEventListener('click', exportLogs);
}

function checkURLParameters() {
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get('id');
  if (scanId) {
    document.getElementById('scanIdInput').value = scanId;
    loadScan(parseInt(scanId));
  }
}

// ============================================================================
// SCAN LOADING
// ============================================================================
async function loadAvailableScans() {
  try {
    const response = await fetch(`${API_V1}/scans/?per_page=50`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error('Failed to load scans');

    const data = await response.json();
    populateScanSelect(data.items || []);
  } catch (error) {
    console.error('Failed to load scans:', error);
  }
}

function populateScanSelect(scans) {
  const select = document.getElementById('scanSelect');
  if (!select) return;

  select.innerHTML = '<option value="">— Select a scan —</option>';
  
  scans.forEach(scan => {
    const option = document.createElement('option');
    option.value = scan.id;
    option.textContent = `#${scan.id} - ${scan.target} (${scan.status})`;
    select.appendChild(option);
  });
}

function handleScanSelectChange(e) {
  const scanId = e.target.value;
  if (scanId) {
    document.getElementById('scanIdInput').value = scanId;
  }
}

function loadSelectedScan() {
  const scanIdInput = document.getElementById('scanIdInput');
  const scanSelect = document.getElementById('scanSelect');
  
  const scanId = scanIdInput?.value || scanSelect?.value;
  
  if (!scanId) {
    alert('Please select or enter a scan ID');
    return;
  }

  loadScan(parseInt(scanId));
}

async function loadScan(scanId) {
  try {
    // Clean up previous scan
    cleanup();

    state.currentScanId = scanId;
    
    // Fetch scan details
    const response = await fetch(`${API_V1}/scans/${scanId}`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error(`Scan #${scanId} not found`);

    const data = await response.json();
    state.scanData = data;
    state.startTime = new Date(data.started_at);

    // Show scan details
    document.getElementById('scanDetails')?.classList.remove('hidden');
    
    // Update UI
    updateScanInfo(data);
    updatePhaseProgress(data);
    
    // Load statistics
    await loadScanStatistics(scanId);
    
    // Start real-time monitoring if scan is running
    if (data.status === 'running') {
      startRealtimeMonitoring(scanId);
    } else if (data.status === 'completed') {
      showSummary();
    }

    // Start duration timer
    startDurationTimer();

  } catch (error) {
    console.error('Failed to load scan:', error);
    alert(error.message);
  }
}

// ============================================================================
// REAL-TIME MONITORING (SSE)
// ============================================================================
function startRealtimeMonitoring(scanId) {
  // Connect to SSE stream
  const sseUrl = `${API_V1}/stream/scan/${scanId}`;
  
  try {
    state.eventSource = new EventSource(sseUrl);
    
    state.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleSSEEvent(data);
      } catch (error) {
        console.error('Failed to parse SSE data:', error);
      }
    };

    state.eventSource.onerror = (error) => {
      console.error('SSE connection error:', error);
      document.getElementById('liveIndicator')?.classList.remove('badge-success');
      document.getElementById('liveIndicator')?.classList.add('badge-danger');
      document.getElementById('liveIndicator').textContent = '● DISCONNECTED';
      
      // Attempt to reconnect after 5 seconds
      setTimeout(() => {
        if (state.currentScanId && state.scanData?.status === 'running') {
          startRealtimeMonitoring(state.currentScanId);
        }
      }, 5000);
    };

    // Update live indicator
    document.getElementById('liveIndicator')?.classList.add('badge-success');
    document.getElementById('liveIndicator').textContent = '● LIVE';

  } catch (error) {
    console.error('Failed to start SSE:', error);
    // Fallback to polling
    startPolling(scanId);
  }
}

function handleSSEEvent(data) {
  const eventType = data.event || data.type;

  switch (eventType) {
    case 'log':
      addLogEntry(data);
      break;
    case 'progress':
      updateProgress(data);
      break;
    case 'phase_change':
      updatePhaseProgress({ current_phase: data.phase });
      break;
    case 'stats':
      updateStats(data);
      break;
    case 'completed':
      handleScanComplete();
      break;
    case 'error':
      handleScanError(data);
      break;
    case 'heartbeat':
      // Keep connection alive
      break;
    default:
      console.log('Unknown SSE event:', eventType, data);
  }
}

function startPolling(scanId) {
  // Fallback polling if SSE not available
  state.updateInterval = setInterval(async () => {
    try {
      const response = await fetch(`${API_V1}/scans/${scanId}`, {
        headers: getHeaders()
      });

      if (response.ok) {
        const data = await response.json();
        updateScanInfo(data);
        updatePhaseProgress(data);

        if (data.status !== 'running') {
          stopPolling();
          if (data.status === 'completed') {
            handleScanComplete();
          }
        }
      }
    } catch (error) {
      console.error('Polling error:', error);
    }
  }, 3000); // Poll every 3 seconds
}

function stopPolling() {
  if (state.updateInterval) {
    clearInterval(state.updateInterval);
    state.updateInterval = null;
  }
}

// ============================================================================
// UI UPDATES
// ============================================================================
function updateScanInfo(data) {
  // Status
  const statusEl = document.getElementById('statusValue');
  if (statusEl) {
    statusEl.textContent = data.status.toUpperCase();
    const statusCard = document.getElementById('statusCard');
    statusCard?.classList.remove('success', 'warning', 'critical');
    if (data.status === 'completed') statusCard?.classList.add('success');
    else if (data.status === 'failed') statusCard?.classList.add('critical');
    else if (data.status === 'running') statusCard?.classList.add('warning');
  }

  document.getElementById('statusTime').textContent = formatDateTime(data.started_at);

  // Progress
  const progress = data.progress_percentage || 0;
  document.getElementById('progressValue').textContent = `${progress}%`;
  document.getElementById('overallProgress').style.width = `${progress}%`;
  
  if (progress >= 90) {
    document.getElementById('overallProgress').classList.add('success');
  } else if (progress >= 60) {
    document.getElementById('overallProgress').classList.remove('danger');
  } else if (progress < 30) {
    document.getElementById('overallProgress').classList.add('danger');
  }

  // Target
  document.getElementById('targetValue').textContent = data.target || '—';
  document.getElementById('scanId').textContent = `ID: ${data.id}`;

  // Current phase
  const phase = data.current_phase || 0;
  document.getElementById('currentPhase').textContent = `Phase ${phase}`;
}

function updatePhaseProgress(data) {
  const currentPhase = data.current_phase || 0;
  const phaseSteps = document.querySelectorAll('.phase-step');

  phaseSteps.forEach((step, index) => {
    step.classList.remove('active', 'completed');
    if (index < currentPhase) {
      step.classList.add('completed');
    } else if (index === currentPhase) {
      step.classList.add('active');
    }
  });
}

function updateProgress(data) {
  const progress = data.progress || data.percentage || 0;
  document.getElementById('progressValue').textContent = `${progress}%`;
  document.getElementById('overallProgress').style.width = `${progress}%`;
}

function updateStats(data) {
  state.stats = {
    subdomains: data.subdomains || state.stats.subdomains,
    ports: data.ports || state.stats.ports,
    services: data.services || state.stats.services,
    vulnerabilities: data.vulnerabilities || state.stats.vulnerabilities
  };

  animateCounter('subdomainCount', state.stats.subdomains);
  animateCounter('portCount', state.stats.ports);
  animateCounter('serviceCount', state.stats.services);
  animateCounter('vulnCount', state.stats.vulnerabilities);
}

function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const current = parseInt(el.textContent) || 0;
  if (current === targetValue) return;

  const duration = 300;
  const startTime = performance.now();
  const diff = targetValue - current;

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const value = Math.floor(current + diff * easeOutQuad(progress));
    el.textContent = value;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = targetValue;
    }
  }

  requestAnimationFrame(update);
}

function easeOutQuad(t) {
  return t * (2 - t);
}

// ============================================================================
// LOGS
// ============================================================================
function addLogEntry(data) {
  const logStream = document.getElementById('logStream');
  if (!logStream) return;

  // Remove empty state if present
  const emptyState = logStream.querySelector('.empty-state');
  if (emptyState) {
    emptyState.remove();
  }

  const timestamp = new Date().toLocaleTimeString();
  const message = data.message || data.log || JSON.stringify(data);
  const level = data.level || 'info';

  const logLine = document.createElement('div');
  logLine.className = 'log-line';
  logLine.innerHTML = `
    <span class="timestamp">[${timestamp}]</span>
    <span class="level-${level}">${level.toUpperCase()}</span>
    <span>${escapeHtml(message)}</span>
  `;

  logStream.appendChild(logLine);
  state.logs.push({ timestamp, level, message });

  // Auto-scroll if enabled
  const autoScroll = document.getElementById('autoScrollCheck')?.checked;
  if (autoScroll) {
    logStream.scrollTop = logStream.scrollHeight;
  }

  // Limit log entries to prevent memory issues
  if (state.logs.length > 1000) {
    const firstLine = logStream.querySelector('.log-line');
    firstLine?.remove();
    state.logs.shift();
  }
}

function clearLogs() {
  const logStream = document.getElementById('logStream');
  if (!logStream) return;

  logStream.innerHTML = '<div class="empty-state"><p class="text-muted">Logs cleared</p></div>';
  state.logs = [];
}

function exportLogs() {
  if (state.logs.length === 0) {
    alert('No logs to export');
    return;
  }

  const content = state.logs.map(log => 
    `[${log.timestamp}] ${log.level.toUpperCase()}: ${log.message}`
  ).join('\n');

  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan_${state.currentScanId}_logs_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================================================
// SCAN ACTIONS
// ============================================================================
async function handleScanAction(action) {
  if (!state.currentScanId) return;

  const confirmMsg = action === 'stop' 
    ? 'Are you sure you want to stop this scan? This cannot be undone.'
    : `Are you sure you want to ${action} this scan?`;

  if (!confirm(confirmMsg)) return;

  try {
    const response = await fetch(`${API_V1}/scans/${state.currentScanId}/${action}`, {
      method: 'POST',
      headers: getHeaders()
    });

    if (!response.ok) throw new Error(`Failed to ${action} scan`);

    addLogEntry({
      level: 'warning',
      message: `Scan ${action} requested by user`
    });

    // Refresh scan status
    setTimeout(() => loadScan(state.currentScanId), 1000);

  } catch (error) {
    console.error(`Failed to ${action} scan:`, error);
    alert(error.message);
  }
}

// ============================================================================
// SCAN STATISTICS
// ============================================================================
async function loadScanStatistics(scanId) {
  try {
    // Load subdomain count
    const subdomainsResponse = await fetch(`${API_V1}/assets/subdomains?scan_run_id=${scanId}&per_page=1`, {
      headers: getHeaders()
    });
    if (subdomainsResponse.ok) {
      const data = await subdomainsResponse.json();
      state.stats.subdomains = data.total || 0;
    }

    // Load vulnerability count
    const findingsResponse = await fetch(`${API_V1}/findings/?scan_run_id=${scanId}&per_page=1`, {
      headers: getHeaders()
    });
    if (findingsResponse.ok) {
      const data = await findingsResponse.json();
      state.stats.vulnerabilities = data.total || 0;
    }

    updateStats(state.stats);
  } catch (error) {
    console.error('Failed to load statistics:', error);
  }
}

// ============================================================================
// COMPLETION HANDLING
// ============================================================================
function handleScanComplete() {
  cleanup();
  
  addLogEntry({
    level: 'success',
    message: '✓ Scan completed successfully!'
  });

  showSummary();
}

function handleScanError(data) {
  addLogEntry({
    level: 'error',
    message: data.message || 'Scan encountered an error'
  });

  document.getElementById('statusValue').textContent = 'FAILED';
  document.getElementById('statusCard')?.classList.add('critical');
}

async function showSummary() {
  const summaryCard = document.getElementById('summaryCard');
  if (!summaryCard) return;

  summaryCard.classList.remove('hidden');

  // Populate summary
  document.getElementById('summaryAssets').textContent = state.stats.subdomains + state.stats.ports;
  document.getElementById('summaryFindings').textContent = state.stats.vulnerabilities;
  
  // Load critical count
  try {
    const response = await fetch(`${API_V1}/findings/by-severity?scan_run_id=${state.currentScanId}`, {
      headers: getHeaders()
    });
    if (response.ok) {
      const data = await response.json();
      document.getElementById('summaryCritical').textContent = data.critical || 0;
    }
  } catch (error) {
    console.error('Failed to load severity stats:', error);
  }

  // Calculate duration
  if (state.scanData?.completed_at) {
    const start = new Date(state.scanData.started_at);
    const end = new Date(state.scanData.completed_at);
    document.getElementById('summaryDuration').textContent = formatDuration(start, end);
  }
}

// ============================================================================
// DURATION TIMER
// ============================================================================
function startDurationTimer() {
  state.updateInterval = setInterval(() => {
    if (!state.startTime) return;

    const now = new Date();
    const duration = formatDuration(state.startTime, now);
    document.getElementById('durationValue').textContent = duration;

    // Estimate ETA if scan is running
    if (state.scanData?.status === 'running') {
      const progress = state.scanData.progress_percentage || 0;
      if (progress > 10) {
        const elapsed = now - state.startTime;
        const total = elapsed / (progress / 100);
        const remaining = total - elapsed;
        document.getElementById('etaValue').textContent = `ETA: ${formatDuration(null, null, remaining)}`;
      }
    }
  }, 1000);
}

// ============================================================================
// CLEANUP
// ============================================================================
function cleanup() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }

  stopPolling();

  document.getElementById('liveIndicator')?.classList.remove('badge-success');
  document.getElementById('liveIndicator')?.classList.add('badge-info');
  document.getElementById('liveIndicator').textContent = '● OFFLINE';
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

function formatDateTime(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  return date.toLocaleString();
}

function formatDuration(start, end, milliseconds = null) {
  let diff;
  if (milliseconds !== null) {
    diff = milliseconds;
  } else if (start && end) {
    diff = end - start;
  } else {
    return '0s';
  }

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  cleanup();
});
