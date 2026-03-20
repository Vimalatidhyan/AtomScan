/**
 * Technieum Enterprise — Dashboard v2.0
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
  initNotifBell();
  bindEvents();
  loadDashboard();
  state.timer = setInterval(() => loadDashboard(true), 30000);
  connectAlertStream();
});

function bindEvents() {
  el('startScan')?.addEventListener('click', startScan);
  el('refreshTargets')?.addEventListener('click', () => loadDashboard());
  // Always force test-mode OFF — real scans only. Clear any stale localStorage value
  // that could have been set by the old Settings toggle.
  localStorage.removeItem('technieum_test_mode');
  const tmBox = el('testMode');
  if (tmBox) tmBox.checked = false;
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
      api('/scans/')
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
    const latestScan = state.scans.find(s => s.target === t);
    const isCompleted = latestScan && latestScan.status === 'completed';
    const card = document.createElement('div');
    card.className = 'stat-card';
    card.style.cursor = 'pointer';
    card.innerHTML = `
      <div class="stat-label truncate">${esc(t)}</div>
      <div class="stat-value" style="font-size:1.25rem;">${scanCount}</div>
      <div class="stat-change"><span class="muted">${scanCount === 1 ? 'scan' : 'scans'}</span></div>
      ${isCompleted ? `<a href="/graph?target=${encodeURIComponent(t)}" class="btn btn-ghost btn-sm" style="margin-top:6px;font-size:0.7rem;" onclick="event.stopPropagation();">View Attack Graph</a>` : ''}
    `;
    card.onclick = () => window.location.href = isCompleted ? `/graph?target=${encodeURIComponent(t)}` : `/assessments`;
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
        <a href="/assessments?id=${esc(s.scan_id)}" class="btn btn-ghost btn-sm">View</a>
        ${s.status === 'completed' ? `<a href="/graph?target=${encodeURIComponent(s.target)}" class="btn btn-ghost btn-sm" style="color:var(--accent);">Graph</a>` : ''}
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
  const testMode = false; // always run real scans; test mode requires TECHNIEUM_TEST_MODE=1 env var
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
    const res = await fetch(`${API}/scans/?${params}`, {
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

// ─── Notification Bell ──────────────────────────────────────────────────────
let _notifications = [];
let _notifPanelOpen = false;

// Comprehensive noise patterns — keep in sync with common.js _NOISE_PATTERNS
const _NOISE_PATTERNS_DASH = [
  'not found', 'not set', 'not installed', 'not a git repo',
  'install:', 'missing', 'skipping', 'falling back', 'relying on',
  'no output', 'no scan targets', 'no scan hosts', 'no subdomains',
  'no javascript', 'no wordlist', 'creating basic', 'failed or timed out',
  'api credentials not set', 'api_key not set', 'not yet available',
  'requires libpostal', 'requires sudo', 'passive enum',
  'subcommand not available', 'subfinder covers', 'not yet run',
  '[inf]', '[wrn]',
];

function isToolNoiseWarn(msg) {
  const lower = String(msg || '').toLowerCase();
  return _NOISE_PATTERNS_DASH.some(p => lower.includes(p));
}

function _fmtNotifTime(d) {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function _renderDashNotifPanel() {
  const panel = el('notifPanel');
  if (!panel) return;
  if (_notifications.length === 0) {
    panel.innerHTML = '<div class="notif-empty">No notifications</div>';
    return;
  }
  panel.innerHTML =
    `<div class="notif-header">
       <span>Notifications (${_notifications.length})</span>
       <button onclick="_clearDashNotif()" class="notif-clear-btn">Clear all</button>
     </div>` +
    _notifications.slice(0, 30).map(n =>
      `<div class="notif-item notif-${n.type}">
         <span class="notif-icon">${n.type === 'error' ? '\u2715' : '\u26a0'}</span>
         <div class="notif-body">
           <div class="notif-msg">${(n.msg || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').slice(0,300)}</div>
           <div class="notif-time">${_fmtNotifTime(n.ts)}</div>
         </div>
       </div>`
    ).join('');
}

function _clearDashNotif() {
  _notifications.length = 0;
  const badge = document.querySelector('.notif-badge');
  if (badge) badge.style.display = 'none';
  _renderDashNotifPanel();
}

function addNotification(msg, type = 'error') {
  _notifications.unshift({ msg: String(msg || ''), type, ts: new Date() });
  if (_notifications.length > 50) _notifications.pop();

  const badge = document.querySelector('.notif-badge');
  if (badge) {
    badge.textContent = _notifications.length;
    badge.style.display = 'inline-flex';
  }

  const short = String(msg).length > 90 ? String(msg).slice(0, 90) + '\u2026' : String(msg);
  if (typeof toast === 'function') toast(short, type === 'error' ? 'error' : 'warning');

  _renderDashNotifPanel();
}

function initNotifBell() {
  const bell  = el('notifBell');
  const panel = el('notifPanel');
  if (!bell || !panel) return;

  // Inject shared panel styles once
  if (!document.getElementById('_notifStyles')) {
    const s = document.createElement('style');
    s.id = '_notifStyles';
    s.textContent = `
      .notif-panel-wrap { position:relative; display:inline-block; }
      #notifPanel {
        display:none; position:absolute; right:0; top:calc(100% + 8px);
        width:340px; max-height:420px; overflow-y:auto;
        background:rgba(18,14,6,0.95); border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; box-shadow:0 8px 32px rgba(0,0,0,.55); z-index:9999;
        font-size:.8125rem; backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
      }
      #notifPanel.open { display:block; }
      .notif-header {
        display:flex; justify-content:space-between; align-items:center;
        padding:.65rem 1rem; border-bottom:1px solid rgba(255,255,255,0.06);
        font-weight:600; color:var(--text,rgba(255,255,255,0.87));
      }
      .notif-clear-btn {
        background:none; border:none; color:var(--text-secondary,rgba(255,255,255,0.60));
        cursor:pointer; font-size:.75rem;
      }
      .notif-clear-btn:hover { color:var(--danger,#FF3B30); }
      .notif-empty {
        padding:1.25rem 1rem; text-align:center;
        color:var(--text-muted,rgba(255,255,255,0.40));
      }
      .notif-item {
        display:flex; gap:.6rem; padding:.65rem 1rem;
        border-bottom:1px solid rgba(255,255,255,0.06);
        align-items:flex-start;
      }
      .notif-item:last-child { border-bottom:none; }
      .notif-icon {
        font-size:.7rem; margin-top:2px; flex-shrink:0;
        width:18px; height:18px; border-radius:50%;
        display:inline-flex; align-items:center; justify-content:center;
      }
      .notif-error .notif-icon { background:var(--danger-bg,rgba(255,59,48,.12)); color:var(--danger,#FF3B30); }
      .notif-warning .notif-icon { background:rgba(255,216,77,.12); color:#FFD84D; }
      .notif-msg { color:var(--text,rgba(255,255,255,0.87)); line-height:1.4; word-break:break-word; }
      .notif-time { color:var(--text-muted,rgba(255,255,255,0.40)); font-size:.7rem; margin-top:.2rem; }
      .notif-badge {
        display:none; position:absolute; top:-4px; right:-4px;
        min-width:16px; height:16px; border-radius:8px;
        background:var(--danger,#FF3B30); color:#fff;
        font-size:.6rem; font-weight:700;
        align-items:center; justify-content:center; padding:0 3px;
        pointer-events:none;
      }
    `;
    document.head.appendChild(s);
  }

  bell.addEventListener('click', (e) => {
    e.stopPropagation();
    _notifPanelOpen = !_notifPanelOpen;
    panel.classList.toggle('open', _notifPanelOpen);
    _renderDashNotifPanel();
  });

  document.addEventListener('click', () => {
    if (_notifPanelOpen) {
      _notifPanelOpen = false;
      panel.classList.remove('open');
    }
  });
}

// ─── Sidebar Toggle ──────────────────────────────────────────────────────────
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
        // Strip ANSI escape codes
        msg = msg.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[\d+(?:;\d+)*m/g, '');
        // Suppress raw JSON tool output (e.g. dnsx, httpx records)
        if (msg.trim()[0] === '{') return;
        const severity = d.severity || d.level || 'info';
        // Suppress tool-availability noise (applies to warnings AND errors)
        if (isToolNoiseWarn(msg)) return;
        // Error/warning alerts → persistent notification panel
        if (severity === 'critical' || severity === 'error') {
          addNotification(msg, 'error');
          loadDashboard(true);
        } else if (severity === 'warning') {
          addNotification(msg, 'warning');
        } else {
          toast(msg, 'info');
        }
      } catch {
        if (msg && !isToolNoiseWarn(msg)) toast(msg, 'info');
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
