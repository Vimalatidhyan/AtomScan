/**
 * ReconX Enterprise — Scan Monitor v2.0
 * Wired to: GET /api/v1/scans, POST /api/v1/scans, GET /api/v1/scans/{id}/status,
 *           GET /api/v1/assets/stats/{t}, GET /api/v1/stream/logs/{id}
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
  scans: [],
  activeScan: null,
  eventSource: null,
  filter: 'all',
  timer: null
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  bindEvents();
  loadScans();
  state.timer = setInterval(() => loadScans(true), 15000);
});

function bindEvents() {
  document.querySelectorAll('.tab[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => setFilter(btn.dataset.filter));
  });
  el('searchInput')?.addEventListener('input', renderScans);
  el('newAssessmentBtn')?.addEventListener('click', () => toggleModal(true));
  el('closeNewAssessment')?.addEventListener('click', () => toggleModal(false));
  el('cancelNewAssessment')?.addEventListener('click', () => toggleModal(false));
  el('submitNewAssessment')?.addEventListener('click', submitNewScan);
  el('closeScanDetail')?.addEventListener('click', closeScanDetail);
}

// ─── Data ─────────────────────────────────────────────────────────────────────
async function loadScans(silent = false) {
  try {
    const data = await apiGet('/scans');
    state.scans = (data?.scans || []).sort((a, b) =>
      new Date(b.started_at || 0) - new Date(a.started_at || 0)
    );
    updateTabCounts();
    renderScans();
  } catch (err) {
    console.error('Failed to load scans:', err);
    if (!silent) toast('Failed to connect to API', 'error');
  }
}

async function loadScanDetail(scanId) {
  try {
    const data = await apiGet(`/scans/${encodeURIComponent(scanId)}/status`);
    state.activeScan = data;
    renderScanDetail(data);
    openScanDetail();
    connectLogStream(scanId);

    // Load target stats
    if (data.target) {
      try {
        const stats = await apiGet(`/assets/stats/${encodeURIComponent(data.target)}`);
        renderScanStats(stats);
      } catch { /* ok */ }
    }
  } catch (err) {
    toast('Failed to load scan details', 'error');
  }
}

// ─── Rendering ────────────────────────────────────────────────────────────────
function updateTabCounts() {
  const counts = { all: 0, running: 0, completed: 0, failed: 0 };
  state.scans.forEach(s => {
    counts.all++;
    if (s.status === 'running') counts.running++;
    else if (s.status === 'completed') counts.completed++;
    else if (s.status === 'failed' || s.status === 'error') counts.failed++;
  });
  const idMap = { all: 'tabAll', running: 'tabRunning', completed: 'tabCompleted', failed: 'tabFailed' };
  Object.entries(idMap).forEach(([k, id]) => {
    const badge = el(id);
    if (badge) badge.textContent = counts[k];
  });
}

function renderScans() {
  const tbody = el('assessmentTable');
  if (!tbody) return;

  const search = el('searchInput')?.value.toLowerCase() || '';
  const filtered = state.scans.filter(s => {
    if (state.filter !== 'all') {
      if (state.filter === 'failed') {
        if (s.status !== 'failed' && s.status !== 'error') return false;
      } else if (s.status !== state.filter) return false;
    }
    if (search) {
      return (s.target || '').toLowerCase().includes(search) ||
             (s.scan_id || '').toLowerCase().includes(search);
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:2.5rem;">
      ${state.filter !== 'all' ? 'No' : 'No'} ${state.filter === 'all' ? '' : state.filter} assessments found.
    </td></tr>`;
    const info = el('paginationInfo');
    if (info) info.textContent = 'Showing 0 assessments';
    return;
  }

  tbody.innerHTML = filtered.map((s, i) => {
    const phaseItems = s.phases ? Object.entries(s.phases) : [];
    const completedPhases = phaseItems.filter(([, done]) => done).length;
    const totalPhases = Math.max(phaseItems.length, 1);
    const progress = Math.round((completedPhases / totalPhases) * 100);
    const phaseStr = phaseItems.map(([k]) => k.split('_')[0]).join(', ') || '1,2,3,4';

    return `<tr onclick="loadScanDetail('${esc(s.scan_id)}')" style="cursor:pointer;">
      <td>${esc(s.name || s.target)}</td>
      <td><span class="font-mono">${esc(s.target)}</span></td>
      <td>${phaseStr}</td>
      <td><span class="status status-${s.status === 'error' ? 'failed' : s.status}">${s.status}</span></td>
      <td class="text-muted">${fmtTime(s.started_at)}</td>
      <td>
        <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>
        <span class="text-muted" style="font-size:0.6875rem">${progress}%</span>
      </td>
      <td class="table-actions">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();loadScanDetail('${esc(s.scan_id)}')">
          Details
        </button>
      </td>
    </tr>`;
  }).join('');

  // Update pagination info
  const info = el('paginationInfo');
  if (info) info.textContent = `Showing ${filtered.length} of ${state.scans.length} assessments`;
}

function renderScanDetail(data) {
  const title = el('detailTitle');
  if (title) title.textContent = `${data.target || 'Scan'} — ${data.status || ''}`;

  // Phase steps
  const container = el('phaseSteps');
  if (!container) return;
  const phases = data.phases || {};
  const phaseNames = {
    '1_discovery': { num: '1', name: 'Subdomain Enumeration' },
    '2_intel': { num: '2', name: 'Port Scanning & Intel' },
    '3_content': { num: '3', name: 'Web Discovery' },
    '4_vuln': { num: '4', name: 'Vulnerability Scan' }
  };

  container.innerHTML = Object.entries(phaseNames).map(([key, info]) => {
    const done = phases[key] === true;
    const status = done ? 'completed' : (data.status === 'running' ? 'in-progress' : 'pending');
    return `<div class="phase-step ${status}">
      <div class="phase-indicator">${done ? '✓' : info.num}</div>
      <div class="phase-info">
        <div class="phase-name">Phase ${info.num}: ${info.name}</div>
        <div class="phase-status">${done ? 'Completed' : (status === 'in-progress' ? 'In Progress' : 'Pending')}</div>
      </div>
    </div>`;
  }).join('');

  // Update progress bar
  const completedCount = Object.values(phases).filter(v => v === true).length;
  const progressPct = Math.round((completedCount / 4) * 100);
  const bar = el('detailProgress');
  if (bar) bar.style.width = `${progressPct}%`;
}

function renderScanStats(stats) {
  if (!stats) return;
  animateNum('detailSubs', stats.subdomains || 0);
  animateNum('detailPorts', stats.open_ports || 0);
  animateNum('detailVulns', stats.vulnerabilities || 0);
  animateNum('detailCritical', stats.critical_vulns || 0);
}

// ─── Log Stream ───────────────────────────────────────────────────────────────
function connectLogStream(scanId) {
  disconnectLogStream();
  const container = el('logStream');
  if (!container) return;
  container.innerHTML = '<div class="text-muted" style="padding:0.5rem;">Connecting to log stream...</div>';

  try {
    state.eventSource = new EventSource(`${API}/stream/logs/${encodeURIComponent(scanId)}`);

    state.eventSource.onmessage = (e) => {
      const line = document.createElement('div');
      line.className = 'log-line';
      let text = e.data || '';
      // Backend sends JSON-wrapped lines: {"line":"..."} or {"msg":"..."}
      try {
        const parsed = JSON.parse(text);
        text = parsed.line || parsed.msg || text;
      } catch { /* plain text fallback */ }
      if (text.includes('ERROR') || text.includes('CRITICAL')) line.classList.add('error');
      else if (text.includes('WARNING')) line.classList.add('warning');
      else if (text.includes('SUCCESS') || text.includes('COMPLETE')) line.classList.add('success');
      line.textContent = text;
      container.appendChild(line);
      container.scrollTop = container.scrollHeight;
    };

    state.eventSource.onerror = () => {
      const line = document.createElement('div');
      line.className = 'log-line text-muted';
      line.textContent = '— Stream disconnected —';
      container.appendChild(line);
      disconnectLogStream();
    };
  } catch {
    container.innerHTML = '<div class="text-muted" style="padding:0.5rem;">Log streaming not available</div>';
  }
}

function disconnectLogStream() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
}

// ─── Scan Detail Panel ────────────────────────────────────────────────────────
function openScanDetail() {
  el('scanDetailCard')?.classList.remove('hidden');
}

function closeScanDetail() {
  el('scanDetailCard')?.classList.add('hidden');
  disconnectLogStream();
  state.activeScan = null;
}

// ─── Tab Filter ───────────────────────────────────────────────────────────────
function setFilter(status) {
  state.filter = status;
  document.querySelectorAll('.tab[data-filter]').forEach(b => b.classList.remove('active'));
  document.querySelector(`.tab[data-filter="${status}"]`)?.classList.add('active');
  renderScans();
}

// ─── New Assessment Modal ─────────────────────────────────────────────────────
function toggleModal(show) {
  const modal = el('newAssessmentModal');
  if (!modal) return;
  if (show) {
    modal.classList.add('open');
    el('modalTarget')?.focus();
  } else {
    modal.classList.remove('open');
    clearModalForm();
  }
}

function clearModalForm() {
  ['modalTarget', 'modalPhases'].forEach(id => { if (el(id)) el(id).value = ''; });
  if (el('modalTestMode')) el('modalTestMode').checked = false;
}

async function submitNewScan() {
  const target = el('modalTarget')?.value.trim();
  const phases = el('modalPhases')?.value.trim() || '1,2,3,4';
  const testMode = el('modalTestMode')?.checked || false;
  const btn = el('submitNewAssessment');

  if (!target) { toast('Target is required', 'error'); return; }

  btn.disabled = true;
  btn.textContent = 'Starting...';

  try {
    const params = new URLSearchParams({ target, phases, test_mode: testMode });
    const res = await fetch(`${API}/scans?${params}`, {
      method: 'POST',
      headers: hdrs()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    toast('Assessment started: ' + data.scan_id, 'success');
    toggleModal(false);
    setTimeout(() => loadScans(), 500);
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Start Assessment';
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function hdrs() { return { 'X-API-Key': localStorage.getItem('reconx_api_key') || 'demo_key' }; }

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

function fmtTime(str) {
  if (!str) return '—';
  const d = new Date(str);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
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

function showMsg(el_, text, type) {
  if (!el_) return;
  el_.textContent = text;
  el_.style.display = 'block';
  el_.style.padding = '8px 12px';
  el_.style.borderRadius = '6px';
  el_.style.fontSize = '0.8125rem';
  el_.style.color = type === 'error' ? 'var(--danger)' : 'var(--success)';
  el_.style.background = type === 'error' ? 'var(--danger-bg)' : 'var(--success-bg)';
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

// ─── Sidebar ──────────────────────────────────────────────────────────────────
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

// Expose functions used in inline HTML handlers
window.loadScanDetail = loadScanDetail;

window.addEventListener('beforeunload', () => {
  disconnectLogStream();
  if (state.timer) clearInterval(state.timer);
});
