/**
 * Technieum Enterprise — Scan Monitor v2.0
 * Wired to: GET /api/v1/scans, POST /api/v1/scans, GET /api/v1/scans/{id}/status,
 *           GET /api/v1/assets/stats/{t}, GET /api/v1/stream/logs/{id}
 */

const API = '/api/v1';

function ensureApiKey() {
  /* No-op: API key auth disabled. */
}

let state = {
  scans: [],
  activeScan: null,
  eventSource: null,
  _progressStream: null,
  _lastLogEventId: 0,   // tracks last received event id for SSE resume-on-reconnect
  filter: 'all',
  timer: null
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await ensureApiKey();
  initSidebar();
  initNotifBell();
  bindEvents();
  await loadScans();
  // Auto-open a specific scan when navigated from the dashboard View button
  const autoId = new URLSearchParams(window.location.search).get('id');
  if (autoId) {
    await loadScanDetail(autoId);
    el('scanDetailCard')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  state.timer = visibilityPoll(() => loadScans(true), 15000);
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
  el('closeCTDetails')?.addEventListener('click', closeCTDetailsModal);
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
    connectProgressStream(scanId);
    loadJobStatus(scanId);

    // Load assessment panel data (live hosts, ASN, cloud, CT) immediately
    // from the REST endpoint — this works for completed/running scans
    // without waiting for the SSE stream to replay all events.
    loadAssessmentData(scanId);

    // Load data sources in order: DNS first, then ASN (which depends on DNS for mapping)
    _loadDNSRecords(scanId);
    _loadASNRecords(scanId);
    _loadCertificateRecords(scanId);
    _loadWHOISData(scanId);
    _loadScanDetails(scanId);

    // Bind all scan output files to UI panels (dynamic output binder)
    if (typeof initOutputBinding === 'function') {
      initOutputBinding(scanId);
    }

    // Auto-poll assessment data while scan is running/queued
    _startAssessmentPoll(scanId, data.status);

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

// ─── Assessment Data Loader ───────────────────────────────────────────────────
async function loadAssessmentData(scanId) {
  try {
    const numId = parseInt(scanId, 10);
    const data = await apiGet(`/scans/${numId}/assessment`);
    if (data.live_hosts) renderLiveHostsPanel(data.live_hosts);
    if (data.asn)        renderAsnPanel(data.asn);
    if (data.cloud)      renderCloudPanel(data.cloud);
    if (data.ct)         renderCtPanel(data.ct);
    if (data.httpx_details) renderAssetsPanel(data.httpx_details);
  } catch {
    // Assessment data not available yet — panels will populate via SSE
  }
}

function updateTabCounts() {
  const counts = { all: 0, running: 0, completed: 0, failed: 0 };
  state.scans.forEach(s => {
    counts.all++;
    if (s.status === 'running' || s.status === 'paused') counts.running++;
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
      } else if (state.filter === 'running') {
        if (s.status !== 'running' && s.status !== 'paused') return false;
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

  tbody.innerHTML = filtered.map((s) => {
    const phaseItems = s.phases ? Object.entries(s.phases) : [];
    const completedPhases = phaseItems.filter(([, done]) => done).length;
    const totalPhases = Math.max(phaseItems.length, 1);
    // If scan is completed/failed, clamp progress to 100/0 regardless of phase data
    const progress = s.status === 'completed' ? 100
      : s.status === 'failed' ? 100
      : phaseItems.length === 0 ? (s.status === 'running' ? 5 : 0)
      : Math.round((completedPhases / totalPhases) * 100);
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
        <button class="btn btn-ghost btn-sm" style="color:var(--danger);" onclick="event.stopPropagation();deleteScan('${esc(s.scan_id)}')">
          Remove
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

  // Render action buttons
  const actionsDiv = el('detailActions');
  if (actionsDiv) {
    const status = data.status || '';
    const scanIdVal = data.scan_id || data.id;
    actionsDiv.innerHTML = `
      ${status === 'running'
        ? `<button class="btn btn-ghost btn-sm" style="color:var(--warning,#F59E0B);" data-scan-id="${esc(scanIdVal)}" data-action="pause" title="Pause scan">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
             Pause
           </button>
           <button class="btn btn-ghost btn-sm" data-scan-id="${esc(scanIdVal)}" data-action="stop">Stop</button>`
        : status === 'paused'
        ? `<button class="btn btn-primary btn-sm" data-scan-id="${esc(scanIdVal)}" data-action="resume" title="Resume scan">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
             Resume
           </button>
           <button class="btn btn-ghost btn-sm" data-scan-id="${esc(scanIdVal)}" data-action="stop">Stop</button>`
        : `<button class="btn btn-ghost btn-sm" data-scan-id="${esc(scanIdVal)}" data-action="start">Retry</button>`}
      <button class="btn btn-ghost btn-sm" style="color:var(--danger);" data-scan-id="${esc(scanIdVal)}" data-action="delete">Delete</button>`;
    // Delegate clicks on action buttons
    actionsDiv.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.scanId;
        const act = btn.dataset.action;
        if (act === 'stop') stopScan(id);
        else if (act === 'start') startScan(id);
        else if (act === 'delete') deleteScan(id);
        else if (act === 'pause') pauseScan(id);
        else if (act === 'resume') resumeScan(id);
      });
    });
  }

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
  animateNum('detailSubs',        stats.subdomains    || 0);
  animateNum('detailPorts',       stats.ports         || stats.open_ports || 0);
  animateNum('detailVulns',       stats.vulnerabilities || 0);
  animateNum('detailCritical',    stats.critical      || stats.critical_vulns || 0);
  animateNum('detailCloudAssets', stats.cloud_assets  || 0);
}

// ─── Tool output formatter ────────────────────────────────────────────────────
function formatToolLine(text) {
  if (!text) return text;
  try {
    const obj = JSON.parse(text);
    if (Array.isArray(obj)) {
      // Array tool output — summarise
      return obj.slice(0, 3).map(v => (typeof v === 'object' ? formatToolLine(JSON.stringify(v)) : String(v))).join(' | ');
    }
    // dnsx: {"host":"x","status_code":"NOERROR","a":["1.2.3.4"],"cname":["..."]}
    if (obj.host && obj.status_code !== undefined) {
      const cname = obj.cname?.length ? ` → ${obj.cname[obj.cname.length - 1]}` : '';
      const ips   = obj.a?.length    ? '  A: ' + obj.a.slice(0, 4).join(', ')    : '';
      return `[DNS] ${obj.host}${cname}${ips}  (${obj.status_code})`;
    }
    // subjack / SubOver: {"subdomain":"x","cname":"y","provider":"z","vulnerable":true}
    if (obj.subdomain && obj.provider !== undefined) {
      return `[Takeover] ${obj.subdomain} → ${obj.provider}${obj.vulnerable ? '  ⚠ VULNERABLE' : ''}`;
    }
    // gau / waybackurls: plain URL lines come as strings, but JSON fallback
    if (obj.uri || obj.url) {
      return `[URL] ${obj.uri || obj.url}${obj.status_code ? '  ' + obj.status_code : ''}`;
    }
    // gospider / hakrawler / cariddi: {"input":"...","output":"...","source":"..."}
    if (obj.input && obj.output) {
      return `[Crawl] ${obj.output}${obj.source ? '  (' + obj.source + ')' : ''}`;
    }
    // Generic: show up to 5 key=value pairs, truncated
    return Object.entries(obj).slice(0, 5)
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v).slice(0, 60) : String(v).slice(0, 80)}`)
      .join('  ');
  } catch {
    return text;
  }
}

// ─── Panel data store ─────────────────────────────────────────────────────────
const _panelData = { liveHosts: [], asn: {}, cloud: {}, ct: {}, assets: [], dns: [], certificates: [], whois: {}, logs: [] };

// ─── Panel toggle ─────────────────────────────────────────────────────────────
function tmTogglePanel(panelId) {
  el(panelId)?.classList.toggle('collapsed');
}

// ─── Live Hosts Panel ─────────────────────────────────────────────────────────
function renderLiveHostsPanel(data) {
  const urls  = data.urls || data.hosts || [];
  const count = data.count || urls.length;
  _panelData.liveHosts = urls;
  animateNum('detailLiveHosts', count);
  const badge = el('liveHostsBadge');
  if (badge) badge.textContent = count;
  const body = el('liveHostsPanelBody');
  if (!body) return;
  if (!urls.length) { body.innerHTML = '<div class="tm-empty">No live hosts detected.</div>'; return; }
  body.innerHTML = `<div class="tm-hosts-grid">${
    urls.slice(0, 200).map(u =>
      `<div class="tm-host-item"><a href="${esc(u)}" target="_blank" rel="noopener" style="color:var(--primary);text-decoration:none;">${esc(u)}</a></div>`
    ).join('')
  }${urls.length > 200 ? `<div class="tm-empty" style="grid-column:1/-1;">…and ${urls.length - 200} more</div>` : ''}</div>`;
}

// ─── ASN Panel ────────────────────────────────────────────────────────────────
function renderAsnPanel(data) {
  const cidrs     = data.cidrs       || [];
  const ipCount   = data.ip_count    || 0;
  const ipsSample = data.ips_sample  || [];
  _panelData.asn = data;
  const badge = el('asnCidrBadge');
  if (badge) badge.textContent = cidrs.length;
  const body = el('asnPanelBody');
  if (!body) return;
  if (!cidrs.length && !ipsSample.length) {
    body.innerHTML = '<div class="tm-empty">No ASN data detected.</div>'; return;
  }
  const cidrHtml = cidrs.length ? `<div style="margin-bottom:.75rem;">
    <div style="font-size:.72rem;font-weight:600;color:var(--text-secondary);margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.05em;">CIDRs (${cidrs.length})</div>
    <div class="tm-cidr-list">${cidrs.map(c => `<span class="tm-cidr-tag">${esc(c)}</span>`).join('')}</div>
  </div>` : '';
  const ipHtml = ipCount ? `<div style="font-size:.8125rem;color:var(--text-secondary);">
    IP range contains <strong style="color:var(--text-primary);">${ipCount.toLocaleString()}</strong> addresses
    ${ipsSample.length ? `&mdash; sample: <span class="font-mono" style="font-size:.72rem;">${ipsSample.slice(0,6).map(esc).join(', ')}</span>` : ''}
  </div>` : '';
  body.innerHTML = cidrHtml + ipHtml;
}

// ─── Cloud Panel ──────────────────────────────────────────────────────────────
function renderCloudPanel(data) {
  const total = data.total || 0;
  const aws   = data.aws   || [];
  const azure = data.azure || [];
  const gcp   = data.gcp   || [];
  const all   = data.assets || [];
  _panelData.cloud = data;
  animateNum('detailCloudAssets', total);
  const badge = el('cloudBadge');
  if (badge) badge.textContent = total;
  const body = el('cloudPanelBody');
  if (!body) return;
  if (!total) { body.innerHTML = '<div class="tm-empty">No cloud assets detected.</div>'; return; }
  function vendorBlock(name, cls, items) {
    if (!items.length) return '';
    return `<div class="tm-cloud-vendor">
      <div class="tm-cloud-vendor-name ${cls}">${name} (${items.length})</div>
      ${items.slice(0,20).map(i => `<div class="tm-cloud-item">${esc(typeof i === 'string' ? i : JSON.stringify(i))}</div>`).join('')}
      ${items.length > 20 ? `<div style="font-size:.7rem;color:var(--text-secondary);margin-top:.25rem;">…and ${items.length-20} more</div>` : ''}
    </div>`;
  }
  const uncat = all.filter(a => !aws.includes(a) && !azure.includes(a) && !gcp.includes(a));
  const html = [vendorBlock('AWS','aws',aws), vendorBlock('Azure','azure',azure), vendorBlock('GCP','gcp',gcp), vendorBlock('Other','aws',uncat)].join('');
  body.innerHTML = html
    ? `<div class="tm-cloud-grid">${html}</div>`
    : `<div class="tm-empty">${total} cloud assets recorded (no vendor breakdown).</div>`;
}

// ─── Certificate Transparency Panel ───────────────────────────────────────────
function renderCtPanel(data) {
  _panelData.ct = data;
  const body = el('ctPanelBody');
  if (!body) return;
  const certspotter = data.certspotter || 0;
  const crtsh       = data.crtsh       || 0;
  const total       = data.total       || (certspotter + crtsh);
  const badge = el('ctBadge');
  if (badge) badge.textContent = total;
  if (!total) { body.innerHTML = '<div class="tm-empty">No CT data recorded.</div>'; return; }
  body.innerHTML = `<div class="tm-ct-stats">
    <div class="tm-ct-stat" style="cursor:pointer;" onclick="openCTDetailsModal()"><span class="tm-ct-stat-val">${total.toLocaleString()}</span><span class="tm-ct-stat-lbl">Total CT Entries</span></div>
    ${certspotter ? `<div class="tm-ct-stat" style="cursor:pointer;" onclick="openCTDetailsModal()"><span class="tm-ct-stat-val">${certspotter.toLocaleString()}</span><span class="tm-ct-stat-lbl">CertSpotter</span></div>` : ''}
    ${crtsh ? `<div class="tm-ct-stat" style="cursor:pointer;" onclick="openCTDetailsModal()"><span class="tm-ct-stat-val">${crtsh.toLocaleString()}</span><span class="tm-ct-stat-lbl">crt.sh</span></div>` : ''}
  </div>`;
}

// ─── Discovered Assets (HTTPx Details) Panel ──────────────────────────────────
function renderAssetsPanel(data) {
  const hosts = data.hosts || [];
  _panelData.assets = hosts;
  const badge = el('assetsBadge');
  if (badge) badge.textContent = hosts.length;
  const body = el('assetsPanelBody');
  if (!body) return;
  if (!hosts.length) { body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">No host detail data available.</div>'; return; }
  const statusClass = (code) => {
    const c = parseInt(code, 10);
    if (c >= 500) return 's5xx';
    if (c >= 400) return 's4xx';
    if (c >= 300) return 's3xx';
    return 's2xx';
  };
  const rows = hosts.slice(0, 300).map(h => {
    const host = h.host || h.url || h.input || '';
    const ip = h.a ? (Array.isArray(h.a) ? h.a[0] : h.a) : (h.ip || '');
    const port = h.port || '';
    const status = h.status_code || '';
    const tech = (h.tech || h.technologies || []);
    const techStr = Array.isArray(tech) ? tech.join(', ') : String(tech || '');
    const title = h.title || '';
    const server = h.webserver || '';
    return `<tr>
      <td>${esc(host)}</td>
      <td>${esc(String(ip))}</td>
      <td>${esc(String(port))}</td>
      <td>${status ? `<span class="tm-status-badge ${statusClass(status)}">${esc(String(status))}</span>` : ''}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;" title="${esc(title)}">${esc(title)}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;">${esc(server)}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${esc(techStr)}">${esc(techStr)}</td>
    </tr>`;
  }).join('');
  body.innerHTML = `<table class="tm-assets-table">
    <thead><tr><th>Host</th><th>IP</th><th>Port</th><th>Status</th><th>Title</th><th>Server</th><th>Technology</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>${hosts.length > 300 ? `<div class="tm-empty" style="padding:.5rem 1rem;">Showing 300 of ${hosts.length} hosts</div>` : ''}`;
}

// ─── DNS Resolution Panel ────────────────────────────────────────────────────
function renderDNSPanel(data) {
  // Handle both old and new API formats
  const records = data.records || [];
  const allRecords = records.map(r => ({
    subdomain: r.subdomain || r.domain || "",
    ip: r.ip || "N/A",
    cname: r.cname || "N/A",
    ttl: r.ttl || "N/A",
    resolver: r.resolver || "N/A",
    asn: r.asn || "N/A",
    country: r.country || "Unknown",
    isp: r.isp || "Unknown",
  }));

  _panelData.dns = allRecords;
  const badge = el('dnsBadge');
  if (badge) badge.textContent = allRecords.length;

  const body = el('dnsPanelBody');
  if (!body) return;

  if (!allRecords.length) {
    body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">No DNS records found or scanning in progress...</div>';
    return;
  }

  const rows = allRecords.slice(0, 200).map(r => `<tr>
    <td><small>${esc(r.subdomain || "Unknown")}</small></td>
    <td><code>${esc(r.ip || "N/A")}</code></td>
    <td><code>${esc((r.cname || "").substring(0, 40))}</code></td>
    <td><small>${esc(r.ttl || "N/A")}</small></td>
    <td><small>${esc(r.resolver || "N/A")}</small></td>
  </tr>`).join('');

  body.innerHTML = `<table class="tm-dns-table">
    <thead><tr><th>Subdomain</th><th>IP Address</th><th>CNAME</th><th>TTL</th><th>Resolver</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>${allRecords.length > 200 ? `<div class="tm-empty" style="padding:.5rem 1rem;">Showing 200 of ${allRecords.length} records</div>` : ''}`;
}

// ─── Load DNS Records ────────────────────────────────────────────────────────
async function _loadDNSRecords(scanId) {
  try {
    const data = await apiGet(`/scans/${parseInt(scanId, 10)}/dns-records`);
    if (data && (data.records || data.dns_records)) {
      renderDNSPanel(data);
    }
  } catch (err) {
    console.debug('DNS records not available:', err);
  }
}

// ─── Load Certificate Records ───────────────────────────────────────────────
async function _loadCertificateRecords(scanId) {
  try {
    const data = await apiGet(`/scans/${parseInt(scanId, 10)}/certificate-records`);
    if (data && data.certificates) {
      _panelData.certificates = data.certificates;
      // Update CT badge with certificate count
      const badge = el('ctBadge');
      if (badge) badge.textContent = (data.count || data.certificates.length || 0).toString();
    }
  } catch (err) {
    console.debug('Certificate records not available:', err);
  }
}

// ─── Load ASN Records ───────────────────────────────────────────────────────
async function _loadASNRecords(scanId) {
  try {
    const data = await apiGet(`/scans/${parseInt(scanId, 10)}/asn-records`);
    console.log('ASN records loaded:', data);
    if (data) {
      const records = data.asn_records || [];
      const count = data.count || records.length || 0;
      console.log(`ASN: ${count} records found`);
      
      if (count > 0) {
        renderASNIPTable(records);
        
        // Update badge with record count
        const badge = el('asnCidrBadge');
        if (badge) {
          badge.textContent = count.toString();
          badge.style.display = 'inline-block';
        }
      } else {
        // No data found
        const body = el('asnPanelBody');
        if (body) body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">No ASN data available</div>';
        const badge = el('asnCidrBadge');
        if (badge) badge.style.display = 'none';
      }
    }
  } catch (err) {
    console.warn('ASN records not available:', err.message);
    const body = el('asnPanelBody');
    if (body) body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">Failed to load ASN data</div>';
  }
}

// ─── Render ASN & IP Ranges Table ────────────────────────────────────────────
function renderASNIPTable(records) {
  const body = el('asnPanelBody');
  if (!body) return;

  // Flatten records and combine with DNS data if available
  const asnIPs = (records || []).map(r => ({
    ip: r.ip || "Unknown",
    asn: r.asn || "unknown",
    organization: r.organization || "unknown",
    subdomain: null, // Will be populated from DNS data
  }));

  // Merge with DNS records to show subdomain → IP → ASN mapping
  const dnsRecords = _panelData.dns || [];
  const dnsMap = {};
  dnsRecords.forEach(dns => {
    if (!dnsMap[dns.ip]) dnsMap[dns.ip] = [];
    dnsMap[dns.ip].push(dns.subdomain);
  });

  // Create combined rows
  const allRows = [];
  const seenIPs = new Set();
  
  asnIPs.forEach(asn => {
    const subdomains = dnsMap[asn.ip] || [];
    if (subdomains.length) {
      subdomains.forEach(subdomain => {
        allRows.push({
          subdomain: subdomain,
          ip: asn.ip,
          asn: asn.asn,
          organization: asn.organization,
        });
      });
    } else {
      allRows.push({
        subdomain: "-",
        ip: asn.ip,
        asn: asn.asn,
        organization: asn.organization,
      });
    }
    seenIPs.add(asn.ip);
  });

  // Remove duplicate IP rows (keep first occurrence)
  const dedupRows = [];
  const addedIPs = new Set();
  allRows.forEach(row => {
    if (!addedIPs.has(row.ip)) {
      dedupRows.push(row);
      addedIPs.add(row.ip);
    }
  });

  _panelData.asn = dedupRows;

  if (!dedupRows.length) {
    body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">No ASN records found.</div>';
    return;
  }

  const rows = dedupRows.slice(0, 200).map(r => `<tr>
    <td><small>${esc(r.subdomain || "-")}</small></td>
    <td><code>${esc(r.ip)}</code></td>
    <td><small>${esc(r.asn || "unknown")}</small></td>
    <td><small>${esc((r.organization || "unknown").substring(0, 50))}</small></td>
  </tr>`).join('');

  body.innerHTML = `<table class="tm-asn-table" style="width:100%;border-collapse:collapse;font-size:.8rem;">
    <thead style="background-color:var(--bg-secondary);border-bottom:1px solid var(--border-color);">
      <tr>
        <th style="padding:.5rem;text-align:left;font-weight:600;">Subdomain</th>
        <th style="padding:.5rem;text-align:left;font-weight:600;">IP Address</th>
        <th style="padding:.5rem;text-align:left;font-weight:600;">ASN</th>
        <th style="padding:.5rem;text-align:left;font-weight:600;">Organization</th>
      </tr>
    </thead>
    <tbody style="border-bottom:1px solid var(--border-color);">
      ${rows}
    </tbody>
  </table>${dedupRows.length > 200 ? `<div class="tm-empty" style="padding:.5rem 1rem;font-size:.75rem;">Showing 200 of ${dedupRows.length} records</div>` : ''}`;
}

// ─── Load WHOIS Data ────────────────────────────────────────────────────────
async function _loadWHOISData(scanId) {
  try {
    const data = await apiGet(`/scans/${parseInt(scanId, 10)}/whois-data`);
    console.log('WHOIS data loaded:', data);
    if (data) {
      _panelData.whois = data;
      const hasData = (data.domain_info && Object.keys(data.domain_info).length > 0) ||
                      (data.registrant_info && Object.keys(data.registrant_info).length > 0) ||
                      (data.contact_info && Object.keys(data.contact_info).length > 0) ||
                      (data.name_servers && data.name_servers.length > 0);
      console.log(`WHOIS: Data found = ${hasData}`);
      renderWHOISPanel(data);
    }
  } catch (err) {
    console.warn('WHOIS data not available:', err.message);
    const body = el('whoisPanelBody');
    if (body) body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">Failed to load WHOIS data</div>';
  }
}

// ─── Render WHOIS / Domain Intelligence Panel ───────────────────────────────
function renderWHOISPanel(data) {
  const body = el('whoisPanelBody');
  if (!body) return;

  const domainInfo = data.domain_info || {};
  const registrantInfo = data.registrant_info || {};
  const contactInfo = data.contact_info || {};
  const nameServers = data.name_servers || [];

  // Check if we have any actual data
  const hasData = Object.keys(domainInfo).length > 0 || 
                  Object.keys(registrantInfo).length > 0 || 
                  Object.keys(contactInfo).length > 0 || 
                  nameServers.length > 0;

  if (!hasData) {
    body.innerHTML = '<div class="tm-empty" style="padding:.75rem 1rem;">No WHOIS data available</div>';
    // Hide badge if no data
    const badge = el('whoisBadge');
    if (badge) badge.style.display = 'none';
    return;
  }
  
  // Show badge when data is available
  const badge = el('whoisBadge');
  if (badge) {
    badge.textContent = '1';
    badge.style.display = 'inline-block';
  }

  let html = '<div style="padding:1rem;">';

  // Domain Information Section
  if (Object.keys(domainInfo).length > 0) {
    html += '<div style="margin-bottom:1.5rem;"><div style="font-weight:600;color:var(--brand-orange);margin-bottom:.5rem;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px;">Domain Information</div>';
    if (domainInfo.domain_name) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Domain Name</span><span style="font-weight:500;">${esc(domainInfo.domain_name)}</span></div>`;
    if (domainInfo.registrar) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Registrar</span><span style="font-weight:500;">${esc(domainInfo.registrar)}</span></div>`;
    if (domainInfo.registry_domain_id) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Registry ID</span><span style="font-weight:500;font-family:monospace;font-size:0.85rem;">${esc(domainInfo.registry_domain_id)}</span></div>`;
    if (domainInfo.last_modified) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Last Modified</span><span style="font-weight:500;">${esc(domainInfo.last_modified)}</span></div>`;
    if (domainInfo.dnssec) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">DNSSEC</span><span style="font-weight:500;color:#22C55E;">${esc(domainInfo.dnssec)}</span></div>`;
    if (domainInfo.status) {
      const statuses = Array.isArray(domainInfo.status) ? domainInfo.status : [domainInfo.status];
      html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Status</span><span style="font-weight:500;font-size:0.85rem;color:#F59E0B;">${esc(statuses.join(', '))}</span></div>`;
    }
    html += '</div>';
  }

  // Registrant Information Section
  if (Object.keys(registrantInfo).length > 0) {
    html += '<div style="margin-bottom:1.5rem;"><div style="font-weight:600;color:var(--brand-orange);margin-bottom:.5rem;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px;">Registrant Information</div>';
    if (registrantInfo.name) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Organization</span><span style="font-weight:500;">${esc(registrantInfo.name)}</span></div>`;
    else if (registrantInfo.organization) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Organization</span><span style="font-weight:500;">${esc(registrantInfo.organization)}</span></div>`;
    if (registrantInfo.contact_name) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Contact Name</span><span style="font-weight:500;">${esc(registrantInfo.contact_name)}</span></div>`;
    if (registrantInfo.eligibility_type) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Eligibility</span><span style="font-weight:500;">${esc(registrantInfo.eligibility_type)}</span></div>`;
    html += '</div>';
  }

  // Contact Information Section
  if (Object.keys(contactInfo).length > 0) {
    html += '<div style="margin-bottom:1.5rem;"><div style="font-weight:600;color:var(--brand-orange);margin-bottom:.5rem;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px;">Contact Information</div>';
    if (contactInfo.abuse_email) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Abuse Email</span><span style="font-weight:500;color:#06B6D4;"><a href="mailto:${esc(contactInfo.abuse_email)}" style="color:inherit;text-decoration:underline;">${esc(contactInfo.abuse_email)}</a></span></div>`;
    if (contactInfo.abuse_phone) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Abuse Phone</span><span style="font-weight:500;">${esc(contactInfo.abuse_phone)}</span></div>`;
    if (contactInfo.tech_contact) html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="color:var(--text-secondary);">Tech Contact</span><span style="font-weight:500;">${esc(contactInfo.tech_contact)}</span></div>`;
    html += '</div>';
  }

  // Name Servers Section
  if (nameServers.length > 0) {
    html += '<div style="margin-bottom:0.5rem;"><div style="font-weight:600;color:var(--brand-orange);margin-bottom:.5rem;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px;">Name Servers</div>';
    nameServers.forEach(ns => {
      const nsName = ns.name ? esc(ns.name) : 'Unknown';
      const nsIP = ns.ip ? esc(ns.ip) : 'N/A';
      html += `<div style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,0.06);"><span style="font-family:monospace;font-size:0.85rem;color:var(--text-secondary);">${nsName}</span><span style="font-weight:500;color:#22D3EE;">${nsIP}</span></div>`;
    });
    html += '</div>';
  }

  html += '</div>';
  body.innerHTML = html;
  
  // Ensure any previous placeholder/empty state is removed
  const emptyStates = body.querySelectorAll('.tm-empty');
  emptyStates.forEach(el => el.remove());
}

// ─── Load Scan Details ───────────────────────────────────────────────────────
async function _loadScanDetails(scanId) {
  try {
    const data = await apiGet(`/scans/${parseInt(scanId, 10)}/scan-details`);
    if (data && data.assets) {
      _panelData.scanDetails = data.assets;
      const badge = el('detailsBadge');
      if (badge) badge.textContent = (data.count || 0).toString();
    }
  } catch (err) {
    console.debug('Scan details not available:', err);
  }
}

// ─── Certificate Details Modal ──────────────────────────────────────────────
function openCTDetailsModal() {
  const modal = el('ctDetailsModal');
  if (!modal) return;
  modal.classList.add('open');
  renderCTCertificatesList(_panelData.certificates || []);
}

function closeCTDetailsModal() {
  const modal = el('ctDetailsModal');
  if (modal) modal.classList.remove('open');
}

function renderCTCertificatesList(certificates) {
  const container = el('ctCertsList');
  if (!container) return;
  if (!certificates || !certificates.length) {
    container.innerHTML = '<div class="tm-empty">No certificates found. Reload data or wait for scan to complete.</div>';
    return;
  }
  container.innerHTML = certificates.slice(0, 500).map(cert => `<div class="tm-cert-record">
    <div class="tm-cert-header">
      <span class="tm-cert-domain">${esc(cert.domain || cert.common_name || 'Unknown')}</span>
      <span class="tm-cert-source">[${esc(cert.source || 'Unknown')}]</span>
    </div>
    <div class="tm-cert-details">
      ${cert.issuer ? `<div class="tm-cert-detail"><div class="tm-cert-label">Issuer</div><div class="tm-cert-value">${esc(cert.issuer)}</div></div>` : ''}
      ${cert.ca ? `<div class="tm-cert-detail"><div class="tm-cert-label">CA</div><div class="tm-cert-value">${esc(cert.ca)}</div></div>` : ''}
      ${cert.valid_from ? `<div class="tm-cert-detail"><div class="tm-cert-label">Valid From</div><div class="tm-cert-value">${esc(cert.valid_from)}</div></div>` : ''}
      ${cert.valid_to ? `<div class="tm-cert-detail"><div class="tm-cert-label">Valid To</div><div class="tm-cert-value">${esc(cert.valid_to)}</div></div>` : ''}
      ${cert.fingerprint ? `<div class="tm-cert-detail"><div class="tm-cert-label">SHA256</div><div class="tm-cert-value" style="font-size:.65rem;word-break:break-all;">${esc(cert.fingerprint)}</div></div>` : ''}
    </div>
    ${cert.sans && cert.sans.length ? `<div class="tm-cert-sans-container"><div class="tm-cert-label">SANs</div><ul class="tm-cert-sans">${(cert.sans || []).map(s => `<li>${esc(s)}</li>`).join('')}</ul></div>` : ''}
  </div>`).join('');
}

// ─── Export helpers ───────────────────────────────────────────────────────────
function rxExport(type, format) {
  let content = '', filename = `technieum-${type}.${format}`;
  if (type === 'liveHosts') {
    const d = _panelData.liveHosts;
    if (!d?.length) { toast('No live host data to export', 'error'); return; }
    content = format === 'json' ? JSON.stringify(d, null, 2) : d.join('\n');
  } else if (type === 'asn') {
    const d = _panelData.asn;
    // Handle both old format (cidrs list) and new format (table rows)
    if (Array.isArray(d) && d.length) {
      // New table format: array of {subdomain, ip, asn, organization}
      if (format === 'json') {
        content = JSON.stringify(d, null, 2);
      } else if (format === 'csv') {
        const rows = [['subdomain','ip_address','asn','organization']];
        d.forEach(r => {
          rows.push([r.subdomain || '', r.ip || '', r.asn || 'unknown', r.organization || 'unknown']);
        });
        content = rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
      }
    } else if (d?.cidrs?.length) {
      // Old format: cidrs object with cidrs array
      content = format === 'json' ? JSON.stringify(d, null, 2) : (d.cidrs || []).join('\n');
    } else {
      toast('No ASN data to export', 'error'); 
      return;
    }
  } else if (type === 'cloud') {
    const d = _panelData.cloud;
    if (!d?.total) { toast('No cloud data to export', 'error'); return; }
    if (format === 'json') content = JSON.stringify(d, null, 2);
    else if (format === 'csv') {
      const rows = [['vendor','asset']];
      (d.aws||[]).forEach(a=>rows.push(['AWS',a]));
      (d.azure||[]).forEach(a=>rows.push(['Azure',a]));
      (d.gcp||[]).forEach(a=>rows.push(['GCP',a]));
      content = rows.map(r=>r.join(',')).join('\n');
    }
  } else if (type === 'ct') {
    const d = _panelData.ct;
    if (!d || !(d.total || d.certspotter || d.crtsh)) { toast('No CT data to export', 'error'); return; }
    content = JSON.stringify(d, null, 2);
  } else if (type === 'dns') {
    const d = _panelData.dns;
    if (!d?.length) { toast('No DNS data to export', 'error'); return; }
    if (format === 'json') {
      content = JSON.stringify(d, null, 2);
    } else if (format === 'csv') {
      const rows = [['subdomain','ip_address','asn','isp','country']];
      d.forEach(r => {
        rows.push([r.subdomain, r.ip, r.asn, r.isp, r.country]);
      });
      content = rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    }
  } else if (type === 'certificates') {
    const d = _panelData.certificates;
    if (!d?.length) { toast('No certificate data to export', 'error'); return; }
    if (format === 'json') {
      content = JSON.stringify(d, null, 2);
    } else if (format === 'csv') {
      const rows = [['domain','issuer','valid_from','valid_to','source']];
      d.forEach(c => {
        rows.push([c.domain||'', c.issuer||'', c.valid_from||'', c.valid_to||'', c.source||'']);
      });
      content = rows.map(r=>r.map(cell=>`"${String(cell).replace(/"/g,'""')}"`).join(',')).join('\n');
    }
  } else if (type === 'assets') {
    const d = _panelData.assets;
    if (!d?.length) { toast('No asset data to export', 'error'); return; }
    if (format === 'json') {
      content = JSON.stringify(d, null, 2);
    } else if (format === 'csv') {
      const rows = [['host','ip','port','status_code','title','webserver','technologies']];
      d.forEach(h => {
        const ip = h.a ? (Array.isArray(h.a) ? h.a[0] : h.a) : (h.ip || '');
        const tech = Array.isArray(h.tech || h.technologies) ? (h.tech || h.technologies || []).join(';') : String(h.tech || h.technologies || '');
        rows.push([h.host||h.url||'', ip, h.port||'', h.status_code||'', (h.title||'').replace(/,/g,' '), h.webserver||'', tech]);
      });
      content = rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    }
  } else if (type === 'logs') {
    if (!_panelData.logs?.length) { toast('No log data to export', 'error'); return; }
    content = _panelData.logs.join('\n');
    filename = 'technieum-logs.txt';
  } else if (type === 'whois') {
    const d = _panelData.whois;
    if (!d || !(d.domain_info && Object.keys(d.domain_info).length > 0)) { 
      toast('No WHOIS data to export', 'error'); 
      return; 
    }
    // Export as JSON since WHOIS has hierarchical structure
    content = JSON.stringify(d, null, 2);
    filename = `technieum-whois-${d.target || 'domain'}.json`;
  }
  if (!content) { toast('Nothing to export', 'error'); return; }
  const blob = new Blob([content], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function rxClearLogs() {
  const ls = el('logStream');
  if (ls) ls.innerHTML = '';
  _panelData.logs = [];
}

function _streamStatusText() {
  const currentStatus = (state.activeScan?.status || '').toLowerCase();
  if (currentStatus === 'queued') return 'Connected to log stream. Scan is queued (waiting for worker)...';
  if (currentStatus === 'completed') return 'Connected to log stream. Scan already completed — no new live events.';
  if (currentStatus === 'paused') return 'Connected to log stream. Scan is paused — waiting for resume.';
  if (currentStatus === 'failed' || currentStatus === 'stopped') return `Connected to log stream. Scan is ${currentStatus} — no new live events.`;
  return 'Connected to log stream. Waiting for events...';
}

// ─── Log Stream ───────────────────────────────────────────────────────────────
function connectLogStream(scanId) {
  disconnectLogStream();
  const container = el('logStream');
  if (!container) return;
  container.innerHTML = '<div class="text-muted" style="padding:0.5rem;">Connecting to log stream...</div>';
  state._lastLogEventId = 0;
  _connectLogStreamFrom(parseInt(scanId, 10), 0, container);
}

// Internal: create EventSource from a given lastEventId (used for initial connect and reconnect).
function _connectLogStreamFrom(numericId, fromEventId, container) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }

  try {
    const url = fromEventId > 0
      ? `${API}/stream/logs/${numericId}?lastEventId=${fromEventId}`
      : `${API}/stream/logs/${numericId}`;
    state.eventSource = new EventSource(url);
    state.streamEndedNormally = false;
    state.eventSource.onopen = () => {
      // SSE may send only comment keep-alives during long silent phases.
      // Mark stream as connected even when no log events arrive yet.
      const hasRealLogLine = !!container.querySelector('.log-line');
      if (!hasRealLogLine) {
        container.innerHTML = `<div class="text-muted" style="padding:0.5rem;">${_streamStatusText()}</div>`;
      }
    };
    state.eventSource.onmessage = (e) => {
      // Remove transient status placeholder on first real message
      const placeholder = container.querySelector('.text-muted');
      if (placeholder && container.children.length === 1) {
        container.innerHTML = '';
      }
      const line = document.createElement('div');
      line.className = 'log-line';
      let text = e.data || '';
      try {
        const parsed = JSON.parse(text);
        // Backend may send control events: completed, error, heartbeat
        if (parsed.event === 'completed') {
          state.streamEndedNormally = true;
          line.classList.add('success');
          line.textContent = `— Scan finished (${parsed.status || 'completed'}). —`;
          container.appendChild(line);
          container.scrollTop = container.scrollHeight;
          disconnectLogStream();
          return;
        }
        if (parsed.event === 'error') {
          // Route errors to notification panel ONLY — never show inline
          const errMsg = parsed.message || text;
          if (typeof addNotification === 'function') addNotification(errMsg, 'error');
          return;
        }
        if (parsed.event === 'heartbeat') {
          return; // no UI for heartbeat
        }
        // Route structured data events to dedicated panels
        if (parsed.event === 'asn_data')    { renderAsnPanel(parsed.data || {});       return; }
        if (parsed.event === 'cloud_data')  { renderCloudPanel(parsed.data || {});     return; }
        if (parsed.event === 'ct_data')     { renderCtPanel(parsed.data || {});        return; }
        if (parsed.event === 'alive_hosts') { renderLiveHostsPanel(parsed.data || {}); return; }
        if (parsed.event === 'httpx_details') { renderAssetsPanel(parsed.data || {}); return; }

        text = parsed.line || parsed.message || parsed.msg || text;
        // Track last received event id for resume-on-reconnect
        if (parsed.id) state._lastLogEventId = parsed.id;
        // Keep bracket-prefixed log lines (e.g. [INFO], [WARN], timestamps).
        // Only suppress when the payload itself is a nested JSON blob string.
        const trimmed = (text || '').trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
          try {
            const nested = JSON.parse(trimmed);
            if (nested && typeof nested === 'object') return;
          } catch {
            // Not JSON text; keep rendering.
          }
        }
      } catch { /* plain text fallback */ }

      // Strip ANSI escape codes for matching
      const cleanText = text.replace(/\x1b\[[0-9;]*m/g, '');

      // Suppress tool-availability noise warnings (tool not found / not set / skipping)
      if (cleanText.includes('[WARN]') && isToolNoiseWarn(cleanText)) return;

      // Route ERROR / CRITICAL lines to notifications only — do NOT show inline
      // Skip noise-only errors (tool-not-found, amass env, etc.) silently
      if (cleanText.includes('[ERROR]') || cleanText.includes('CRITICAL') ||
          cleanText.includes('Scan failed') || cleanText.includes('harness exited')) {
        if (!isToolNoiseWarn(cleanText) && typeof addNotification === 'function') {
          addNotification(cleanText, 'error');
        }
        return;
      }

      if (cleanText.includes('WARNING') || cleanText.includes('[WARN]')) line.classList.add('warning');
      else if (cleanText.includes('SUCCESS') || cleanText.includes('COMPLETE') || cleanText.includes('[OK]')) line.classList.add('success');
      line.textContent = cleanText;
      _panelData.logs.push(cleanText);
      container.appendChild(line);
      container.scrollTop = container.scrollHeight;
    };

    state.eventSource.onerror = () => {
      if (state.streamEndedNormally) { disconnectLogStream(); return; }
      // Close the dead connection
      disconnectLogStream();
      // Auto-reconnect if the scan is still active — long-running tools like
      // nmap can cause the stream to idle for many minutes without events;
      // we reconnect from the last received event so nothing is replayed.
      const activeScan = state.activeScan;
      if (!activeScan) return;
      const currentStatus = activeScan.status || '';
      if (currentStatus === 'completed' || currentStatus === 'failed' || currentStatus === 'stopped') {
        // Scan is already done — show final message
        const doneLine = document.createElement('div');
        doneLine.className = 'log-line text-muted';
        doneLine.textContent = `— Stream ended (scan ${currentStatus}). —`;
        container.appendChild(doneLine);
        return;
      }
      // Still running — reconnect silently after 3 s with the last known event id.
      // No banner is appended to the log so transient SSE reconnects don't pollute
      // the output with repeated "reconnecting…" noise.
      const resumeFrom = state._lastLogEventId || 0;
      setTimeout(() => {
        if (!state.activeScan) return; // user navigated away
        _connectLogStreamFrom(parseInt(activeScan.scan_id || activeScan.id, 10), resumeFrom, container);
      }, 3000);
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
  if (state._progressStream) {
    state._progressStream.close();
    state._progressStream = null;
  }
}

// ─── Scan Detail Panel ────────────────────────────────────────────────────────
function openScanDetail() {
  el('scanDetailCard')?.classList.remove('hidden');
}

// ─── Assessment auto-poll (while scan is running/queued) ──────────────────────
function _startAssessmentPoll(scanId, initialStatus) {
  _stopAssessmentPoll();
  const status = (initialStatus || '').toLowerCase();
  if (status === 'completed' || status === 'failed' || status === 'stopped') return;
  state._assessmentPoll = setInterval(async () => {
    if (!state.activeScan) { _stopAssessmentPoll(); return; }
    const curStatus = (state.activeScan.status || '').toLowerCase();
    if (curStatus === 'completed' || curStatus === 'failed' || curStatus === 'stopped') {
      // Final load then stop polling
      await loadAssessmentData(scanId);
      if (state.activeScan?.target) {
        try {
          const stats = await apiGet(`/assets/stats/${encodeURIComponent(state.activeScan.target)}`);
          renderScanStats(stats);
        } catch {}
      }
      _stopAssessmentPoll();
      return;
    }
    await loadAssessmentData(scanId);
  }, 20000);
}
function _stopAssessmentPoll() {
  if (state._assessmentPoll) { clearInterval(state._assessmentPoll); state._assessmentPoll = null; }
}

function closeScanDetail() {
  el('scanDetailCard')?.classList.add('hidden');
  disconnectLogStream();
  _stopAssessmentPoll();
  state.activeScan = null;
  // Reset panel data for next scan
  _panelData.liveHosts = [];
  _panelData.asn  = {};
  _panelData.cloud = {};
  _panelData.ct   = {};
  _panelData.assets = [];
  _panelData.dns = [];
  _panelData.certificates = [];
  _panelData.scanDetails = [];
  _panelData.logs  = [];
  // Reset panel bodies to empty state
  ['liveHostsPanelBody','asnPanelBody','cloudPanelBody','ctPanelBody','assetsPanelBody','dnsPanelBody','detailsPanelBody'].forEach(id => {
    const b = el(id);
    if (b) b.innerHTML = '<div class="tm-empty">Waiting for data…</div>';
  });
  const ls = el('logStream');
  if (ls) ls.innerHTML = '<div class="text-center text-muted" style="padding:2rem;">Waiting for log data…</div>';
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
  // testMode checkbox removed — always run real scans
}

async function submitNewScan() {
  const target = el('modalTarget')?.value.trim();
  const phases = el('modalPhases')?.value.trim() || '1,2,3,4';
  const testMode = false; // always run real scans; TECHNIEUM_TEST_MODE=1 env var required for mock mode
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

// ─── Visibility-aware polling ─────────────────────────────────────────────────
function visibilityPoll(fn, intervalMs) {
  let timerId = null;
  function start() { if (timerId !== null) return; timerId = setInterval(fn, intervalMs); }
  function stop() { clearInterval(timerId); timerId = null; }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { stop(); } else { fn(); start(); }
  });
  if (!document.hidden) start();
  return stop;
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

// ─── Scan Actions ─────────────────────────────────────────────────────────────
async function startScan(scanId) {
  const numId = parseInt(scanId, 10);
  try {
    const res = await fetch(`${API}/scans/${numId}/start`, { method: 'POST', headers: hdrs() });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || `HTTP ${res.status}`);
    }
    toast('Scan queued to start', 'success');
    setTimeout(() => loadScans(), 500);
    if (state.activeScan?.scan_id == scanId) loadScanDetail(scanId);
  } catch (err) {
    toast('Start failed: ' + err.message, 'error');
  }
}

async function stopScan(scanId) {
  const numId = parseInt(scanId, 10);
  try {
    await fetch(`${API}/scans/${numId}/stop`, { method: 'POST', headers: hdrs() });
    toast('Stop signal sent', 'success');
    setTimeout(() => loadScans(), 500);
  } catch (err) {
    toast('Stop failed: ' + err.message, 'error');
  }
}

async function pauseScan(scanId) {
  const numId = parseInt(scanId, 10);
  try {
    const res = await fetch(`${API}/scans/${numId}/pause`, { method: 'POST', headers: hdrs() });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || `HTTP ${res.status}`);
    }
    toast('Scan paused', 'success');
    // Update local state and re-render buttons
    if (state.activeScan) state.activeScan.status = 'paused';
    renderScanDetail({ ...state.activeScan, status: 'paused' });
    setTimeout(() => loadScans(), 500);
  } catch (err) {
    toast('Pause failed: ' + err.message, 'error');
  }
}

async function resumeScan(scanId) {
  const numId = parseInt(scanId, 10);
  try {
    const res = await fetch(`${API}/scans/${numId}/resume`, { method: 'POST', headers: hdrs() });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.detail || `HTTP ${res.status}`);
    }
    toast('Scan resumed', 'success');
    // Update local state and re-render buttons
    if (state.activeScan) state.activeScan.status = 'running';
    renderScanDetail({ ...state.activeScan, status: 'running' });
    setTimeout(() => loadScans(), 500);
  } catch (err) {
    toast('Resume failed: ' + err.message, 'error');
  }
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan and all its findings? This cannot be undone.')) return;
  const numId = parseInt(scanId, 10);
  try {
    const res = await fetch(`${API}/scans/${numId}`, { method: 'DELETE', headers: hdrs() });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `HTTP ${res.status}`); }
    toast('Scan deleted', 'success');
    closeScanDetail();
    setTimeout(() => loadScans(), 300);
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
  }
}

async function loadJobStatus(scanId) {
  const numId = parseInt(scanId, 10);
  try {
    const job = await apiGet(`/scans/${numId}/job`);
    const panel = el('jobStatusPanel');
    if (!panel) return;
    const statusClass = job.status === 'done' ? 'completed' : job.status === 'failed' ? 'failed' : job.status;
    panel.innerHTML = `
      <div style="font-size:.75rem;color:var(--text-secondary);margin-bottom:.5rem;">Worker Job</div>
      <div style="display:flex;gap:.75rem;flex-wrap:wrap;font-size:.8125rem;">
        <span>Job&nbsp;<strong>#${esc(job.job_id ?? job.id ?? '—')}</strong></span>
        <span class="status status-${statusClass}">${esc(job.status)}</span>
        ${job.worker_id ? `<span class="text-muted font-mono" style="font-size:.7rem;">${esc(job.worker_id)}</span>` : ''}
        ${job.started_at ? `<span class="text-muted">Started ${fmtTime(job.started_at)}</span>` : ''}
        ${job.finished_at ? `<span class="text-muted">Finished ${fmtTime(job.finished_at)}</span>` : ''}
        ${job.error ? `<span style="color:var(--danger);font-size:.75rem;">${esc(job.error)}</span>` : ''}
      </div>`;
  } catch {
    const panel = el('jobStatusPanel');
    if (panel) panel.innerHTML = '<span class="text-muted" style="font-size:.75rem;">No worker job found</span>';
  }
}

function connectProgressStream(scanId) {
  // Close any existing progress stream first
  if (state._progressStream) {
    state._progressStream.close();
    state._progressStream = null;
  }
  const numId = parseInt(scanId, 10);
  const bar = el('detailProgress');
  if (!bar) return;
  const es = new EventSource(`${API}/stream/progress/${numId}`);
  es.onmessage = (e) => {
    try {
      const d = JSON.parse(e.data);
      const p = d.percentage ?? d.progress_percentage ?? 0;
      bar.style.width = `${p}%`;
      if (d.status === 'completed' || d.status === 'failed') {
        es.close();
        state._progressStream = null;
        setTimeout(() => loadScans(true), 800);
      }
    } catch { /* ignore */ }
  };
  es.onerror = () => {
    es.close();
    state._progressStream = null;
  };
  state._progressStream = es;
}

// Expose functions used in inline HTML handlers
window.loadScanDetail  = loadScanDetail;
window.startScan       = startScan;
window.stopScan        = stopScan;
window.pauseScan       = pauseScan;
window.resumeScan      = resumeScan;
window.deleteScan      = deleteScan;
window.tmTogglePanel   = tmTogglePanel;
window.rxExport        = rxExport;
window.rxClearLogs     = rxClearLogs;

window.addEventListener('beforeunload', () => {
  disconnectLogStream();
  if (state.timer) clearInterval(state.timer);
});
