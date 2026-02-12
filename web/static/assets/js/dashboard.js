const API_BASE = '/api/v1';

async function api(path, options = {}) {
  const res = await fetch(API_BASE + path, options);
  if (!res.ok) throw new Error(res.statusText || res.status);
  if (res.headers.get('content-type')?.includes('application/json')) return res.json();
  return res.text();
}

function showScanMsg(msg, isError = false) {
  const el = document.getElementById('scanMsg');
  el.textContent = msg;
  el.classList.toggle('error-msg', isError);
  el.classList.remove('hidden');
}

function hideScanMsg() {
  document.getElementById('scanMsg').classList.add('hidden');
}

document.getElementById('startScan').addEventListener('click', async () => {
  const target = document.getElementById('target').value.trim();
  const phases = document.getElementById('phases').value.trim() || '1,2,3,4';
  const testMode = document.getElementById('testMode').checked;
  if (!target) {
    showScanMsg('Enter a target domain.', true);
    return;
  }
  hideScanMsg();
  const btn = document.getElementById('startScan');
  btn.disabled = true;
  btn.classList.add('loading');
  try {
    let url = `/scans?target=${encodeURIComponent(target)}&phases=${encodeURIComponent(phases)}`;
    if (testMode) url += '&test_mode=true';
    const data = await api(url, { method: 'POST' });
    showScanMsg(
      testMode
        ? 'Quick scan started. Results will appear in a few seconds…'
        : 'Scan started. This may take several minutes. Refreshing automatically.',
      false
    );
    loadScans();
    loadTargets();
    startPollingIfNeeded();
  } catch (e) {
    showScanMsg(e.message || 'Failed to start scan', true);
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
});

async function loadTargets() {
  const wrap = document.getElementById('targetsList');
  const loading = document.getElementById('targetsLoading');
  loading.classList.remove('hidden');
  wrap.classList.add('hidden');
  try {
    const data = await api('/assets/targets');
    loading.classList.add('hidden');
    if (!data.targets || data.targets.length === 0) {
      wrap.innerHTML = '<div class="empty-state"><p>No targets in database yet.</p></div>';
      wrap.classList.remove('hidden');
      return;
    }
    const statsPromises = data.targets.map(t => api(`/assets/stats/${encodeURIComponent(t)}`));
    const statsList = await Promise.all(statsPromises);
    wrap.innerHTML = '<div class="stats-grid" id="targetStatsGrid"></div>';
    const grid = document.getElementById('targetStatsGrid');
    data.targets.forEach((target, i) => {
      const s = statsList[i] || {};
      const phaseList = s.phase_list || [];
      const phaseBadges = phaseList.length
        ? phaseList.map(p => `<span class="phase-badge ${p.done ? 'done' : 'pending'}" title="Phase ${p.id}: ${p.name}">${p.id}: ${p.done ? '✓' : '—'}</span>`).join('')
        : '<span class="text-muted">No phase data</span>';
      const box = document.createElement('div');
      box.className = 'card';
      box.style.marginBottom = '0.5rem';
      box.innerHTML = `
        <strong>${escapeHtml(target)}</strong>
        <div class="phase-row" style="margin-top: 0.35rem; font-size: 0.8rem;">
          <span style="color: var(--text-muted); margin-right: 0.5rem;">Phases:</span>
          ${phaseBadges}
        </div>
        <div class="stats-grid" style="margin-top: 0.5rem;">
          <div class="stat-box"><span class="value">${s.subdomains ?? 0}</span><span class="label">Subdomains</span></div>
          <div class="stat-box"><span class="value">${s.alive_hosts ?? 0}</span><span class="label">Alive</span></div>
          <div class="stat-box"><span class="value">${s.urls ?? 0}</span><span class="label">URLs</span></div>
          <div class="stat-box critical"><span class="value">${s.critical_vulns ?? 0}</span><span class="label">Critical</span></div>
          <div class="stat-box high"><span class="value">${s.high_vulns ?? 0}</span><span class="label">High</span></div>
        </div>
      `;
      grid.appendChild(box);
    });
    wrap.classList.remove('hidden');
  } catch (e) {
    loading.textContent = 'Failed to load targets: ' + e.message;
  }
}

async function loadScans() {
  const loading = document.getElementById('scansLoading');
  const list = document.getElementById('scansList');
  const empty = document.getElementById('scansEmpty');
  const tbody = document.getElementById('scansTableBody');
  loading.classList.remove('hidden');
  list.classList.add('hidden');
  empty.classList.add('hidden');
  try {
    const data = await api('/scans');
    loading.classList.add('hidden');
    if (!data.scans || data.scans.length === 0) {
      empty.classList.remove('hidden');
      return;
    }
    tbody.innerHTML = data.scans.slice(0, 20).map(s => {
      const ph = s.phases || {};
      const phaseStr = [1, 2, 3, 4].map(n => {
        const key = n === 1 ? '1_discovery' : n === 2 ? '2_intel' : n === 3 ? '3_content' : '4_vuln';
        return ph[key] ? `${n}✓` : `${n}—`;
      }).join(' ');
      return `
      <tr>
        <td><a href="/findings.html?target=${encodeURIComponent(s.target)}" style="color: var(--accent);">${escapeHtml(s.target)}</a></td>
        <td><span class="status-badge status-${(s.status || 'pending').toLowerCase()}">${escapeHtml(s.status)}</span></td>
        <td>${s.progress ?? 0}%</td>
        <td><span class="phase-cells" title="1=Discovery 2=Intel 3=Content 4=Vuln">${phaseStr || '—'}</span></td>
        <td>${s.started_at ? escapeHtml(s.started_at.replace('T', ' ').slice(0, 19)) : '—'}</td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(s.error || '')}">${escapeHtml((s.error || '').slice(0, 60))}${(s.error || '').length > 60 ? '…' : ''}</td>
      </tr>
    `;
    }).join('');
    list.classList.remove('hidden');
    return data.scans.some(s => (s.status || '').toLowerCase() === 'running');
  } catch (e) {
    loading.textContent = 'Failed to load scans: ' + e.message;
    return false;
  }
}

let pollTimer = null;
function startPollingIfNeeded() {
  if (pollTimer) return;
  function tick() {
    loadScans().then(hasRunning => {
      if (!hasRunning) {
        pollTimer = clearInterval(pollTimer);
        pollTimer = null;
        return;
      }
      loadTargets();
    });
  }
  pollTimer = setInterval(tick, 4000);
  tick();
}

function escapeHtml(s) {
  if (s == null) return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

loadTargets();
loadScans().then(hasRunning => {
  if (hasRunning) startPollingIfNeeded();
});
