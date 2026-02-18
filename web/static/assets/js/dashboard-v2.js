/**
 * ReconX Enterprise — Dashboard v2.0
 * Wired to: GET /api/v1/scans, /api/v1/assets/targets, /api/v1/assets/stats/{t}, /api/v1/findings/{t}/summary
 */

const API = '/api/v1';

function ensureApiKey() {
  /* No-op: API key auth disabled. */
}

const state = {
  targets: [],
  scans: [],
  stats: { critical: 0, high: 0, assets: 0, activeScans: 0 },
  timer: null,
  _alertStream: null
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  bindEvents();
  loadDashboard();
  state.timer = setInterval(() => loadDashboard(true), 30000);
  connectAlertStream();
});

function bindEvents() {
  el('startScan')?.addEventListener('click', startScan);
  el('refreshTargets')?.addEventListener('click', () => loadDashboard());
  checkApiHealth();
}

async function checkApiHealth() {
  const dot = el('apiHealthDot');
  if (!dot) return;
  try {
    const res = await fetch('/api/health');
    dot.style.color = res.ok ? 'var(--green)' : 'var(--red)';
    dot.title = res.ok ? 'API Online' : 'API Error';
  } catch {
    dot.style.color = 'var(--red)';
    dot.title = 'API Offline';
  }
}

// ─── Data Loading ─────────────────────────────────────────────────────────────
async function loadDashboard(silent = false) {
  try {
    const [targetsRes, scansRes] = await Promise.all([
      api('/assets/targets'),
      api('/scans')
    ]);

    const targets = targetsRes?.targets || [];
    const scans = scansRes?.scans || [];

    state.targets = targets;
    state.scans = scans;
    state.stats.assets = targets.length;
    state.stats.activeScans = scans.filter(s => s.status === 'running').length;

    // Aggregate findings across all targets
    let totalCritical = 0, totalHigh = 0;
    const summaryPromises = targets.slice(0, 20).map(t =>
      api(`/findings/${encodeURIComponent(t)}/summary`).catch(() => null)
    );
    const summaries = await Promise.all(summaryPromises);
    summaries.forEach(s => {
      if (s) {
        totalCritical += s.critical || 0;
        totalHigh += s.high || 0;
      }
    });
    state.stats.critical = totalCritical;
    state.stats.high = totalHigh;

    renderStats();
    renderTargets();
    renderScans();

    // Update sidebar badge
    const badge = el('sidebarVulnCount');
    if (badge) badge.textContent = totalCritical + totalHigh;

  } catch (err) {
    console.error('Dashboard load failed:', err);
    if (!silent) toast('Failed to connect to API. Is the server running?', 'error');
    renderOfflineState();
  }
}

// ─── Rendering ────────────────────────────────────────────────────────────────
function renderStats() {
  animateNum('criticalCount', state.stats.critical);
  animateNum('highCount', state.stats.high);
  animateNum('assetCount', state.stats.assets);
  animateNum('activeScanCount', state.stats.activeScans);
}

function renderTargets() {
  const container = el('targetsContainer');
  if (!container) return;

  if (state.targets.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No targets found. Start an assessment to begin monitoring.</p></div>';
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'stats-grid';
  grid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(180px, 1fr))';

  state.targets.slice(0, 8).forEach(t => {
    const scanCount = state.scans.filter(s => s.target === t).length || 1;
    const card = document.createElement('div');
    card.className = 'stat-card';
    card.style.cursor = 'pointer';
    card.innerHTML = `
      <div class="stat-label truncate">${esc(t)}</div>
      <div class="stat-value" style="font-size:1.25rem;">${scanCount}</div>
      <div class="stat-change"><span class="muted">${scanCount === 1 ? 'scan' : 'scans'}</span></div>
    `;
    card.onclick = () => window.location.href = `/assessments`;
    grid.appendChild(card);
  });

  container.innerHTML = '';
  container.appendChild(grid);
}

function renderScans() {
  const tbody = el('scansTableBody');
  if (!tbody) return;

  if (state.scans.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted" style="padding:2rem;">No assessments yet. Start your first scan above.</td></tr>';
    return;
  }

  tbody.innerHTML = state.scans.slice(0, 10).map(s => {
    const phases = s.phases || {};
    const phaseHtml = Object.entries(phases).map(([k, done]) => {
      const num = k.split('_')[0];
      return `<span class="badge ${done ? 'badge-success' : 'badge-info'}" style="font-size:0.625rem;margin-right:2px;">${num}</span>`;
    }).join('');

    return `<tr>
      <td class="font-mono" style="font-size:0.75rem;">${esc(s.scan_id).slice(0, 20)}</td>
      <td><strong>${esc(s.target)}</strong></td>
      <td><span class="status status-${s.status}">${s.status}</span></td>
      <td>${phaseHtml || '—'}</td>
      <td class="text-muted">${fmtTime(s.started_at)}</td>
      <td class="table-actions">
        <a href="/assessments" class="btn btn-ghost btn-sm">View</a>
      </td>
    </tr>`;
  }).join('');
}

function renderOfflineState() {
  const tbody = el('scansTableBody');
  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted" style="padding:2rem;">API offline — start the server with: uvicorn api.server:app --port 8000</td></tr>';
  }
  const container = el('targetsContainer');
  if (container) {
    container.innerHTML = '<div class="empty-state"><p class="text-muted">API server not connected</p></div>';
  }
}

// ─── Actions ──────────────────────────────────────────────────────────────────
async function startScan() {
  const target = el('target')?.value.trim();
  const phases = el('phases')?.value.trim() || '1,2,3,4';
  const testMode = el('testMode')?.checked || false;
  const msg = el('scanMsg');

  if (!target) {
    showMsg(msg, 'Please enter a target domain', 'error');
    return;
  }

  const btn = el('startScan');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;"></span> Starting...';

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
    showMsg(msg, `Assessment started! ID: ${data.scan_id}`, 'success');
    toast('Assessment started successfully', 'success');

    setTimeout(() => loadDashboard(), 1000);
    setTimeout(() => { window.location.href = '/assessments'; }, 2000);

  } catch (err) {
    showMsg(msg, err.message, 'error');
    toast(err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Scan';
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }

function hdrs() {
  return {};
}

async function api(path) {
  const res = await fetch(`${API}${path}`, { headers: hdrs() });
  if (!res.ok) throw new Error(`API error ${res.status}`);
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
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString();
}

function animateNum(id, target) {
  const el_ = el(id);
  if (!el_) return;
  const start = parseInt(el_.textContent) || 0;
  if (start === target) return;
  const duration = 400;
  const t0 = performance.now();
  function tick(now) {
    const p = Math.min((now - t0) / duration, 1);
    el_.textContent = Math.floor(start + (target - start) * p * (2 - p));
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function showMsg(el_, text, type) {
  if (!el_) return;
  el_.textContent = text;
  el_.className = '';
  el_.style.display = 'block';
  el_.style.padding = '10px';
  el_.style.borderRadius = '6px';
  el_.style.fontSize = '0.8125rem';
  if (type === 'error') {
    el_.style.background = 'var(--danger-bg)';
    el_.style.color = 'var(--danger)';
  } else {
    el_.style.background = 'var(--success-bg)';
    el_.style.color = 'var(--success)';
  }
  if (type === 'success') setTimeout(() => { el_.style.display = 'none'; }, 5000);
}

function toast(msg, type = 'info') {
  const container = el('toastContainer');
  if (!container) return;
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ─── Sidebar Toggle ───────────────────────────────────────────────────────────
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
  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar?.classList.remove('open');
      overlay.classList.remove('open');
    });
  }
}

// ─── SSE Alert Stream ─────────────────────────────────────────────────────────
let _alertRetryDelay = 5000;  // start at 5s, back off up to 120s
const _ALERT_MAX_DELAY = 120000;

function connectAlertStream() {
  if (state._alertStream) {
    state._alertStream.close();
    state._alertStream = null;
  }
  try {
    const es = new EventSource(`${API}/stream/alerts`);
    state._alertStream = es;

    es.onopen = () => { _alertRetryDelay = 5000; };  // reset backoff on success

    es.onmessage = (e) => {
      let msg = e.data || '';
      try {
        const d = JSON.parse(msg);
        if (d.event === 'heartbeat') return;  // skip heartbeat events
        msg = d.message || d.msg || d.text || JSON.stringify(d);
        const severity = d.severity || d.level || 'info';
        toast(msg, severity === 'critical' || severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'info');
        if (severity === 'critical' || severity === 'high') loadDashboard(true);
      } catch {
        if (msg) toast(msg, 'info');
      }
    };

    es.onerror = () => {
      if (state._alertStream) {
        state._alertStream.close();
        state._alertStream = null;
      }
      setTimeout(connectAlertStream, _alertRetryDelay);
      _alertRetryDelay = Math.min(_alertRetryDelay * 2, _ALERT_MAX_DELAY);
    };
  } catch {
    // SSE not supported or blocked
  }
}

window.addEventListener('beforeunload', () => {
  if (state.timer) clearInterval(state.timer);
  if (state._alertStream) state._alertStream.close();
});
