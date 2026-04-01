/**
 * Technieum Enterprise — Findings v2.0
 * Wired to: GET /api/v1/assets/targets, GET /api/v1/findings/{target},
 *           GET /api/v1/findings/{target}/summary
 */

const API = '/api/v1';

function ensureApiKey() {
  /* No-op: API key auth disabled. */
}

let state = {
  targets: [],
  findings: [],
  summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  selectedTarget: '',
  severityFilter: 'all',
  page: 1,
  perPage: 25,
  timer: null
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  bindEvents();
  loadTargets();
  state.timer = visibilityPoll(() => { if (state.selectedTarget) loadFindings(true); }, 30000);
});

function bindEvents() {
  el('targetFilter')?.addEventListener('change', onTargetChange);
  el('searchInput')?.addEventListener('input', renderFindings);
  document.querySelectorAll('.tab[data-severity]').forEach(btn => {
    btn.addEventListener('click', () => setSeverityFilter(btn.dataset.severity));
  });
  el('closeFindingModal')?.addEventListener('click', closeDetail);
  el('exportBtn')?.addEventListener('click', exportFindings);
}

// ─── Data ─────────────────────────────────────────────────────────────────────
async function loadTargets() {
  try {
    const data = await apiGet('/assets/targets');
    state.targets = data?.targets || [];
    renderTargetFilter();
    // Auto-select first target
    if (state.targets.length > 0) {
      state.selectedTarget = state.targets[0];
      el('targetFilter').value = state.selectedTarget;
      loadFindings();
    }
  } catch (err) {
    console.error('Targets load failed:', err);
    toast('Failed to connect to API', 'error');
  }
}

async function loadFindings(silent = false) {
  if (!state.selectedTarget) return;
  const target = encodeURIComponent(state.selectedTarget);

  try {
    const [findingsRes, summaryRes] = await Promise.all([
      apiGet(`/findings/${target}`),
      apiGet(`/findings/${target}/summary`)
    ]);

    state.findings = findingsRes?.findings || [];
    state.summary = {
      total: summaryRes?.total || 0,
      critical: summaryRes?.critical || 0,
      high: summaryRes?.high || 0,
      medium: summaryRes?.medium || 0,
      low: summaryRes?.low || 0,
      info: summaryRes?.info || 0
    };

    state.page = 1;
    renderStats();
    updateTabCounts();
    renderFindings();
    loadSeverityChart();
    loadTypeChart();

  } catch (err) {
    console.error('Findings load failed:', err);
    if (!silent) toast('Failed to load findings', 'error');
    state.findings = [];
    state.summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    renderStats();
    renderFindings();
  }
}

function onTargetChange() {
  state.selectedTarget = el('targetFilter')?.value || '';
  if (state.selectedTarget) loadFindings();
}

// ─── Rendering ────────────────────────────────────────────────────────────────
function renderTargetFilter() {
  const select = el('targetFilter');
  if (!select) return;
  select.innerHTML = '<option value="">Select target...</option>' +
    state.targets.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('');
}

function renderStats() {
  animateNum('criticalCount', state.summary.critical);
  animateNum('highCount', state.summary.high);
  animateNum('mediumCount', state.summary.medium);
  animateNum('lowCount', state.summary.low);
}

function updateTabCounts() {
  const f = state.findings;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  f.forEach(finding => {
    const s = sev(finding);
    if (counts[s] !== undefined) counts[s]++;
  });
  const allEl = el('tabAllCount');
  if (allEl) allEl.textContent = f.length;
  const idMap = {
    critical: 'tabCriticalCount',
    high: 'tabHighCount',
    medium: 'tabMediumCount',
    low: 'tabLowCount',
    info: 'tabInfoCount',
  };
  Object.entries(idMap).forEach(([severity, elemId]) => {
    const badge = el(elemId);
    if (badge) badge.textContent = counts[severity];
  });
}

function renderFindings() {
  const tbody = el('findingsTable');
  if (!tbody) return;

  const search = (el('searchInput')?.value || '').toLowerCase();

  let filtered = state.findings;
  if (state.severityFilter !== 'all') {
    filtered = filtered.filter(f => sev(f) === state.severityFilter);
  }
  if (search) {
    filtered = filtered.filter(f =>
      (f.name || f.title || '').toLowerCase().includes(search) ||
      (f.host || '').toLowerCase().includes(search) ||
      (f.cve || '').toLowerCase().includes(search) ||
      (f.tool || '').toLowerCase().includes(search)
    );
  }

  // Pagination
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / state.perPage));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * state.perPage;
  const paged = filtered.slice(start, start + state.perPage);

  const infoEl = el('paginationInfo');
  if (infoEl) infoEl.textContent = total > 0 ? `${start + 1}–${Math.min(start + state.perPage, total)} of ${total}` : '0 findings';

  // Render pagination controls
  const ctrlEl = el('paginationControls');
  if (ctrlEl) {
    ctrlEl.innerHTML = `
      <button class="btn btn-ghost btn-sm" onclick="changePage(-1)" ${state.page <= 1 ? 'disabled' : ''}>&laquo; Prev</button>
      <span class="text-muted" style="padding:0 8px;">Page ${state.page} of ${totalPages}</span>
      <button class="btn btn-ghost btn-sm" onclick="changePage(1)" ${state.page >= totalPages ? 'disabled' : ''}>Next &raquo;</button>
    `;
  }

  if (paged.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:2.5rem;">
      ${state.selectedTarget ? 'No findings match the current filters.' : 'Select a target to view vulnerabilities.'}
    </td></tr>`;
    return;
  }

  tbody.innerHTML = paged.map((f, i) => {
    const severity = sev(f);
    const name = f.name || f.title || 'Unnamed Finding';
    const host = f.host || f.url || '—';
    const cve = f.cve || f.cve_id || '—';
    const tool = f.tool || f.source || '—';
    const discovered = f.discovered_at || f.timestamp || f.created_at || '';

    return `<tr onclick="showDetail(${start + i})" style="cursor:pointer;">
      <td><span class="badge badge-${severity}">${severity.toUpperCase()}</span></td>
      <td><strong>${esc(name)}</strong></td>
      <td class="font-mono" style="font-size:0.75rem;">${esc(host)}</td>
      <td>${cve !== '—' ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(cve)}" target="_blank" class="text-primary">${esc(cve)}</a>` : '—'}</td>
      <td>${esc(tool)}</td>
      <td class="text-muted">${fmtTime(discovered)}</td>
      <td class="table-actions">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();showDetail(${start + i})">Details</button>
      </td>
    </tr>`;
  }).join('');
}

// ─── Detail Modal ─────────────────────────────────────────────────────────────
function showDetail(idx) {
  const f = state.findings[idx];
  if (!f) return;
  const severity = sev(f);

  const sevEl = el('modalSeverity');
  if (sevEl) sevEl.innerHTML = `<span class="badge badge-${severity}" style="font-size:0.9rem;">${severity.toUpperCase()}</span>`;
  const titleEl = el('modalTitle');
  if (titleEl) titleEl.textContent = f.name || f.title || 'Finding';
  const hostEl = el('modalHost');
  if (hostEl) hostEl.textContent = f.host || f.url || '—';
  const cveEl = el('modalCVE');
  if (cveEl) cveEl.textContent = f.cve || f.cve_id || '—';
  const toolEl = el('modalTool');
  if (toolEl) toolEl.textContent = f.tool || f.source || '—';
  const infoEl = el('modalInfo');
  if (infoEl) infoEl.textContent = f.description || f.details || f.info || 'No description available.';

  el('findingModal')?.classList.add('open');
  // Render action buttons using data attributes to avoid XSS
  const actionsEl = el('modalActions');
  if (actionsEl) {
    const fid = f.id;
    actionsEl.innerHTML = '';
    const remBtn = document.createElement('button');
    remBtn.className = 'btn btn-primary btn-sm';
    remBtn.textContent = f.status === 'in_remediation' ? 'In Remediation' : 'Mark Remediation';
    remBtn.disabled = f.status === 'in_remediation';
    remBtn.dataset.findingId = fid;
    remBtn.addEventListener('click', () => remediateFinding(fid));
    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-ghost btn-sm';
    delBtn.style.color = 'var(--danger)';
    delBtn.textContent = 'Delete';
    delBtn.dataset.findingId = fid;
    delBtn.addEventListener('click', () => deleteFinding(fid));
    actionsEl.appendChild(remBtn);
    actionsEl.appendChild(delBtn);
  }
}

function closeDetail() {
  el('findingModal')?.classList.remove('open');
}
window.closeDetail = closeDetail;
window.showDetail = showDetail;
window.changePage = changePage;

// ─── Severity Filter ──────────────────────────────────────────────────────────
function setSeverityFilter(severity) {
  state.severityFilter = severity;
  state.page = 1;
  document.querySelectorAll('.tab[data-severity]').forEach(b => b.classList.remove('active'));
  document.querySelector(`.tab[data-severity="${severity}"]`)?.classList.add('active');
  renderFindings();
}

function changePage(delta) {
  const newPage = state.page + delta;
  if (newPage < 1) return;
  state.page = newPage;
  renderFindings();
  el('findingsTable')?.parentElement?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function hdrs() {
  return {};
}

async function apiGet(path) {
  const res = await fetch(`${API}${path}`, { headers: hdrs() });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

function sev(f) {
  return (f.severity || f.risk || 'info').toLowerCase();
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
  return d.toLocaleDateString();
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

// ─── Visibility-aware polling (fallback if common.js not loaded) ──────────────
if (typeof visibilityPoll === 'undefined') {
  window.visibilityPoll = function(fn, intervalMs) {
    let timerId = null;
    function start() { if (timerId !== null) return; timerId = setInterval(fn, intervalMs); }
    function stop() { clearInterval(timerId); timerId = null; }
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) { stop(); } else { fn(); start(); }
    });
    if (!document.hidden) start();
    return stop;
  };
}

// ─── CSV helpers (fallback if common.js not loaded) ───────────────────────────
if (typeof downloadCsv === 'undefined') {
  window.downloadCsv = function(filename, headers, rows) {
    function escField(val) {
      const s = String(val ?? '').replace(/\r?\n/g, ' ');
      return (s.includes(',') || s.includes('"')) ? `"${s.replace(/"/g, '""')}"` : s;
    }
    const csv = [headers.map(escField).join(','), ...rows.map(r => r.map(escField).join(','))].join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };
}

// ─── Export ────────────────────────────────────────────────────────────────────
function exportFindings() {
  if (state.findings.length === 0) {
    toast('No findings to export', 'warning');
    return;
  }
  const headers = ['Severity', 'Name', 'Host', 'Tool', 'CVE', 'Description', 'Discovered'];
  const rows = state.findings.map(f => [
    sev(f),
    f.name || f.title || '',
    f.host || '',
    f.tool || f.source || '',
    f.cve || f.cve_id || '',
    (f.description || f.info || ''),
    f.discovered_at || ''
  ]);
  downloadCsv(
    `findings_${state.selectedTarget || 'all'}_${new Date().toISOString().slice(0, 10)}.csv`,
    headers, rows
  );
  toast(`Exported ${state.findings.length} findings`, 'success');
}

// ─── Finding Actions ───────────────────────────────────────────────────────────
async function deleteFinding(findingId) {
  if (!confirm('Delete this finding? This cannot be undone.')) return;
  try {
    const res = await fetch(`${API}/findings/${findingId}`, { method: 'DELETE', headers: hdrs() });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `HTTP ${res.status}`); }
    toast('Finding deleted', 'success');
    closeDetail();
    await loadFindings(true);
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
  }
}

async function remediateFinding(findingId) {
  try {
    const res = await fetch(`${API}/findings/${findingId}/remediate`, { method: 'POST', headers: hdrs() });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `HTTP ${res.status}`); }
    toast('Finding marked as in remediation', 'success');
    await loadFindings(true);
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

async function editFinding(findingId, field, value) {
  try {
    const body = { [field]: value };
    const res = await fetch(`${API}/findings/${findingId}`, {
      method: 'PUT',
      headers: { ...hdrs(), 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `HTTP ${res.status}`); }
    toast('Finding updated', 'success');
    await loadFindings(true);
  } catch (err) {
    toast('Update failed: ' + err.message, 'error');
  }
}

async function loadSeverityChart() {
  try {
    const data = await apiGet('/findings/by-severity');
    const container = el('severityChart');
    if (!container) return;
    const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
    const bars = [
      { label: 'Critical', key: 'critical', color: 'var(--danger,#FF2D00)' },
      { label: 'High',     key: 'high',     color: '#FF8C00' },
      { label: 'Medium',   key: 'medium',   color: '#FFD84D' },
      { label: 'Low',      key: 'low',      color: '#ffb84d' },
      { label: 'Info',     key: 'info',     color: '#6b7280' },
    ];
    container.innerHTML = bars.map(b => {
      const count = data[b.key] || 0;
      const pct = Math.round((count / total) * 100);
      return `<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.375rem;font-size:.8125rem;">
        <span style="width:4.5rem;text-align:right;color:var(--text-secondary);">${b.label}</span>
        <div style="flex:1;background:var(--bg-elevated,rgba(255,255,255,0.06));border-radius:3px;height:14px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${b.color};transition:width .4s;"></div>
        </div>
        <span style="width:2.5rem;color:var(--text-secondary);">${count}</span>
      </div>`;
    }).join('');
  } catch { /* non-fatal */ }
}

async function loadTypeChart() {
  try {
    const data = await apiGet('/findings/by-type');
    const container = el('typeChart');
    if (!container) return;
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max = entries[0]?.[1] || 1;
    container.innerHTML = entries.map(([type, count]) => {
      const pct = Math.round((count / max) * 100);
      return `<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.375rem;font-size:.75rem;">
        <span style="width:7rem;text-align:right;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(type)}">${esc(type)}</span>
        <div style="flex:1;background:var(--bg-elevated,rgba(255,255,255,0.06));border-radius:3px;height:12px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:var(--primary,#FF8C00);"></div>
        </div>
        <span style="width:2rem;color:var(--text-secondary);">${count}</span>
      </div>`;
    }).join('') || '<p class="text-muted" style="font-size:.8125rem;padding:.5rem;">No type data yet.</p>';
  } catch { /* non-fatal */ }
}

window.deleteFinding = deleteFinding;
window.remediateFinding = remediateFinding;
window.editFinding = editFinding;

window.addEventListener('beforeunload', () => { if (state.timer) clearInterval(state.timer); });
