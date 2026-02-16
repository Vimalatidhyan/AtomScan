/**
 * ReconX Enterprise — Findings v2.0
 * Wired to: GET /api/v1/assets/targets, GET /api/v1/findings/{target},
 *           GET /api/v1/findings/{target}/summary
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
  state.timer = setInterval(() => { if (state.selectedTarget) loadFindings(true); }, 30000);
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
  const allEl = el('tabAllCount');
  if (allEl) allEl.textContent = f.length;
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

  el('modalSeverity').innerHTML = `<span class="badge badge-${severity}" style="font-size:0.9rem;">${severity.toUpperCase()}</span>`;
  el('modalTitle').textContent = f.name || f.title || 'Finding';
  el('modalHost').textContent = f.host || f.url || '—';
  el('modalCVE').textContent = f.cve || f.cve_id || '—';
  el('modalTool').textContent = f.tool || f.source || '—';
  el('modalInfo').textContent = f.description || f.details || f.info || 'No description available.';

  el('findingModal')?.classList.add('open');
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
  state.page += delta;
  renderFindings();
  el('findingsTable')?.parentElement?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function hdrs() { return { 'X-API-Key': localStorage.getItem('reconx_api_key') || 'demo_key' }; }

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

// ─── Export ────────────────────────────────────────────────────────────────────
function exportFindings() {
  if (state.findings.length === 0) {
    toast('No findings to export', 'warning');
    return;
  }
  const headers = ['Severity', 'Name', 'Host', 'Tool', 'CVE', 'Info', 'Discovered'];
  const rows = state.findings.map(f => [
    sev(f), f.name || '', f.host || '', f.tool || '', f.cve || '', (f.info || '').replace(/"/g, '""'), f.discovered_at || ''
  ]);
  const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `findings_${state.selectedTarget || 'all'}_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  toast(`Exported ${state.findings.length} findings`, 'success');
}

window.addEventListener('beforeunload', () => { if (state.timer) clearInterval(state.timer); });
