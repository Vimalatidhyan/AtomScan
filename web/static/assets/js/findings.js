const API_BASE = '/api/v1';

async function api(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(res.statusText || res.status);
  return res.json();
}

function escapeHtml(s) {
  if (s == null) return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

async function loadTargets() {
  const sel = document.getElementById('targetSelect');
  try {
    const data = await api('/assets/targets');
    sel.innerHTML = '<option value="">— Select target —</option>';
    (data.targets || []).forEach(t => {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = t;
      sel.appendChild(opt);
    });
    const params = new URLSearchParams(location.search);
    const targetFromUrl = params.get('target');
    if (targetFromUrl && data.targets && data.targets.includes(targetFromUrl)) {
      sel.value = targetFromUrl;
      loadFindings();
    }
  } catch (_) {}
}

function showSummary(summary) {
  const grid = document.getElementById('summaryGrid');
  grid.innerHTML = '';
  grid.classList.remove('hidden');
  const items = [
    { label: 'Total', value: summary.total, cls: '' },
    { label: 'Critical', value: summary.critical, cls: 'critical' },
    { label: 'High', value: summary.high, cls: 'high' },
    { label: 'Medium', value: summary.medium, cls: '' },
    { label: 'Low', value: summary.low, cls: '' },
    { label: 'Info', value: summary.info, cls: '' },
  ];
  items.forEach(({ label, value, cls }) => {
    const box = document.createElement('div');
    box.className = 'stat-box ' + cls;
    box.innerHTML = `<div class="value">${value ?? 0}</div><div class="label">${escapeHtml(label)}</div>`;
    grid.appendChild(box);
  });
}

async function loadFindings() {
  const target = document.getElementById('targetSelect').value;
  const severity = document.getElementById('severityFilter').value;
  if (!target) return;

  document.getElementById('summaryLoading').classList.add('hidden');
  document.getElementById('findingsLoading').classList.remove('hidden');
  document.getElementById('findingsList').classList.add('hidden');
  document.getElementById('findingsEmpty').classList.add('hidden');

  try {
    const path = `/findings/${encodeURIComponent(target)}${severity ? '?severity=' + encodeURIComponent(severity) : ''}`;
    const data = await api(path);
    const summaryRes = await api(`/findings/${encodeURIComponent(target)}/summary`);
    showSummary(summaryRes);

    document.getElementById('findingsLoading').classList.add('hidden');
    const list = data.findings || [];
    if (list.length === 0) {
      document.getElementById('findingsEmpty').classList.remove('hidden');
      return;
    }
    const tbody = document.getElementById('findingsTableBody');
    tbody.innerHTML = list.map(f => `
      <tr>
        <td><span class="severity-${escapeHtml((f.severity || 'info').toLowerCase())}">${escapeHtml(f.severity || '')}</span></td>
        <td>${escapeHtml(f.name || '')}</td>
        <td><code>${escapeHtml(f.host || '')}</code></td>
        <td>${escapeHtml(f.tool || '')}</td>
        <td>${escapeHtml(f.cve || '—')}</td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(f.info || '')}">${escapeHtml((f.info || '').slice(0, 80))}${(f.info || '').length > 80 ? '…' : ''}</td>
      </tr>
    `).join('');
    document.getElementById('findingsList').classList.remove('hidden');
  } catch (e) {
    document.getElementById('findingsLoading').classList.add('hidden');
    document.getElementById('findingsLoading').textContent = 'Error: ' + e.message;
    document.getElementById('findingsLoading').classList.remove('hidden');
  }
}

document.getElementById('loadFindings').addEventListener('click', loadFindings);
document.getElementById('targetSelect').addEventListener('change', () => {
  document.getElementById('summaryGrid').classList.add('hidden');
  document.getElementById('summaryLoading').classList.remove('hidden');
});

loadTargets();
