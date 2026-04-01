/**
 * Technieum Enterprise — Shared utilities (common.js)
 * Included by all v2 pages before page-specific scripts.
 *
 * Exports (globals): el, esc, fmtTime, animateNum, toast, initSidebar,
 *   ensureApiKey, hdrs, apiGet, apiPost, apiPut, apiDelete,
 *   visibilityPoll, buildCsv, downloadCsv, showErrorState
 */

// ── DOM helpers ───────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }

function esc(text) {
  const d = document.createElement('div');
  d.textContent = String(text ?? '');
  return d.innerHTML;
}

function fmtTime(str) {
  if (!str) return '—';
  const d = new Date(str);
  if (isNaN(d.getTime())) return String(str);
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

function toast(msg, type = 'info') {
  const c = el('toastContainer');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
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

// ── API (no auth — API key disabled) ──────────────────────────────────────────
function ensureApiKey() {
  /* No-op: API key auth is disabled. Kept for compatibility. */
}

function hdrs(extra = {}) {
  return { ...extra };
}

async function apiGet(path) {
  const res = await fetch(`/api/v1${path}`, { headers: hdrs() });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API ${res.status}`);
  }
  return res.json();
}

async function apiPost(path, body = null, queryParams = null) {
  const url = queryParams
    ? `/api/v1${path}?${new URLSearchParams(queryParams)}`
    : `/api/v1${path}`;
  const opts = { method: 'POST', headers: hdrs() };
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `API ${res.status}`);
  }
  return res.json();
}

async function apiPut(path, body) {
  const res = await fetch(`/api/v1${path}`, {
    method: 'PUT',
    headers: hdrs({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `API ${res.status}`);
  }
  return res.json();
}

async function apiDelete(path) {
  const res = await fetch(`/api/v1${path}`, { method: 'DELETE', headers: hdrs() });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `API ${res.status}`);
  }
  return res.json();
}

// ── Visibility-aware polling ──────────────────────────────────────────────────
/**
 * Create an interval that pauses when the tab is hidden, resumes when visible.
 * @param {Function} fn - Callback to call on each tick
 * @param {number} intervalMs - Milliseconds between ticks
 * @returns {Function} stop - Call to permanently stop the poll
 */
function visibilityPoll(fn, intervalMs) {
  let timerId = null;

  function start() {
    if (timerId !== null) return;
    timerId = setInterval(fn, intervalMs);
  }

  function stop() {
    clearInterval(timerId);
    timerId = null;
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stop();
    } else {
      fn();   // immediate tick on resume
      start();
    }
  });

  if (!document.hidden) start();
  return stop;
}

// ── CSV helpers (RFC 4180) ────────────────────────────────────────────────────
function escapeCsvField(val) {
  const s = String(val ?? '').replace(/\r?\n/g, ' ');
  return (s.includes(',') || s.includes('"') || s.includes('\n'))
    ? `"${s.replace(/"/g, '""')}"`
    : s;
}

function buildCsv(headers, rows) {
  return [
    headers.map(escapeCsvField).join(','),
    ...rows.map(row => row.map(escapeCsvField).join(','))
  ].join('\r\n');
}

function downloadCsv(filename, headers, rows) {
  const blob = new Blob([buildCsv(headers, rows)], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Tool-noise warning filter ───────────────────────────────────────────────
// Shared by scan_monitor_v2.js and dashboard-v2.js to suppress [WARN] lines
// that are purely informational tool-availability notices.
const _NOISE_PATTERNS = [
  'not found', 'not set', 'not installed', 'not a git repo',
  'install:', 'missing', 'skipping', 'falling back', 'relying on',
  'no output', 'no scan targets', 'no scan hosts', 'no subdomains',
  'no javascript', 'no wordlist', 'creating basic', 'failed or timed out',
  'api credentials not set', 'api_key not set', 'not yet available',
];
function isToolNoiseWarn(text) {
  const lower = String(text || '').toLowerCase();
  return _NOISE_PATTERNS.some(p => lower.includes(p));
}

// ── Notification System ─────────────────────────────────────────────────────
const _notifList = [];
let _notifPanelOpen = false;

/**
 * Add a notification to the bell panel (errors/warnings only, never inline).
 * @param {string} msg  - Human-readable message
 * @param {string} type - 'error' | 'warning'
 */
function addNotification(msg, type = 'error') {
  _notifList.unshift({ msg: String(msg || ''), type, ts: new Date() });

  // Light up the bell badge
  const badge = document.querySelector('.notif-badge');
  if (badge) {
    badge.textContent = _notifList.length;
    badge.style.display = 'inline-flex';
  }

  // Also fire a brief toast so the user isn't missed
  const short = msg.length > 90 ? msg.slice(0, 90) + '…' : msg;
  toast(short, type === 'error' ? 'error' : 'warning');

  _renderNotifPanel();
}

function _renderNotifPanel() {
  const panel = el('notifPanel');
  if (!panel) return;
  if (_notifList.length === 0) {
    panel.innerHTML = '<div class="notif-empty">No notifications</div>';
    return;
  }
  panel.innerHTML =
    `<div class="notif-header">
       <span>Notifications (${_notifList.length})</span>
       <button onclick="clearNotifications()" class="notif-clear-btn">Clear all</button>
     </div>` +
    _notifList.slice(0, 30).map(n =>
      `<div class="notif-item notif-${n.type}">
         <span class="notif-icon">${n.type === 'error' ? '✕' : '⚠'}</span>
         <div class="notif-body">
           <div class="notif-msg">${esc(n.msg)}</div>
           <div class="notif-time">${fmtTime(n.ts)}</div>
         </div>
       </div>`
    ).join('');
}

function clearNotifications() {
  _notifList.length = 0;
  const badge = document.querySelector('.notif-badge');
  if (badge) badge.style.display = 'none';
  _renderNotifPanel();
}

/**
 * Wire the notification bell button (#notifBell) to toggle #notifPanel.
 * Call once per page after DOMContentLoaded.
 */
function initNotifBell() {
  const bell  = el('notifBell');
  const panel = el('notifPanel');
  if (!bell || !panel) return;

  // Inject panel styles once
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
    _renderNotifPanel();
  });

  document.addEventListener('click', () => {
    if (_notifPanelOpen) {
      _notifPanelOpen = false;
      panel.classList.remove('open');
    }
  });
}

// ── Error boundary ────────────────────────────────────────────────────────────
/**
 * Replace a container's contents with a user-friendly error state.
 * @param {string} containerId
 * @param {string} message
 * @param {Function|null} retryFn - If provided, a Retry button is shown
 */
function showErrorState(containerId, message, retryFn = null) {
  const c = el(containerId);
  if (!c) return;
  const retryId = `${containerId}-retry-btn`;
  c.innerHTML = `
    <div style="text-align:center;padding:2rem;color:var(--text-secondary);">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--danger,#ef4444)"
           stroke-width="1.5" style="margin-bottom:.75rem;">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <p style="margin:.25rem 0;font-size:.875rem;">${esc(message)}</p>
      ${retryFn ? `<button id="${retryId}" class="btn btn-ghost btn-sm" style="margin-top:.5rem;">Retry</button>` : ''}
    </div>`;
  if (retryFn) el(retryId)?.addEventListener('click', retryFn);
}
