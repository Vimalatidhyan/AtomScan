/**
 * ReconX Enterprise — Shared utilities (common.js)
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

// ── API auth ──────────────────────────────────────────────────────────────────
async function ensureApiKey() {
  const stored = localStorage.getItem('reconx_api_key');
  if (stored && stored !== 'demo_key' && stored.length >= 32) return;
  try {
    const res = await fetch('/api/v1/bootstrap-key');
    if (res.ok) {
      const data = await res.json();
      if (data.key) {
        localStorage.setItem('reconx_api_key', data.key);
        console.log('[ReconX] Bootstrap API key auto-configured');
      }
    }
  } catch { /* ignore network errors during bootstrap */ }
}

function hdrs(extra = {}) {
  const key = localStorage.getItem('reconx_api_key') || '';
  if (!key) console.warn('[ReconX] API key missing — call ensureApiKey() first');
  return { 'X-API-Key': key, ...extra };
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
