/**
 * ReconX Enterprise - Findings v2.0
 * Advanced findings management with filtering, sorting, and bulk actions
 */

const API_BASE = window.location.origin;
const API_V1 = `${API_BASE}/api/v1`;

// State management
const state = {
  findings: [],
  selectedFindings: new Set(),
  currentPage: 1,
  perPage: 25,
  totalFindings: 0,
  totalPages: 0,
  sortBy: 'severity',
  sortOrder: 'desc',
  filters: {
    search: '',
    severity: [],
    type: [],
    status: ['open'],
    scanId: '',
    cvssMin: null,
    cvssMax: null,
    assetType: '',
    dateFrom: null,
    dateTo: null
  },
  stats: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  },
  currentFinding: null
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initializeEventListeners();
  loadScans();
  loadStats();
  loadFindings();
});

function initializeEventListeners() {
  // Search with debounce
  const searchInput = document.getElementById('searchInput');
  let searchTimeout;
  searchInput?.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      state.filters.search = e.target.value;
      state.currentPage = 1;
      loadFindings();
    }, 500);
  });

  // Sort headers
  document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const sortKey = th.dataset.sort;
      if (state.sortBy === sortKey) {
        state.sortOrder = state.sortOrder === 'asc' ? 'desc' : 'asc';
      } else {
        state.sortBy = sortKey;
        state.sortOrder = 'desc';
      }
      loadFindings();
      updateSortIndicators();
    });
  });
}

function updateSortIndicators() {
  document.querySelectorAll('th.sortable').forEach(th => {
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.dataset.sort === state.sortBy) {
      th.classList.add(`sort-${state.sortOrder}`);
    }
  });
}

// ============================================================================
// DATA LOADING
// ============================================================================
async function loadScans() {
  try {
    const response = await fetch(`${API_V1}/scans/?per_page=100`, {
      headers: getHeaders()
    });

    if (!response.ok) return;

    const data = await response.json();
    const scanFilter = document.getElementById('scanFilter');
    if (scanFilter) {
      data.items?.forEach(scan => {
        const option = document.createElement('option');
        option.value = scan.id;
        option.textContent = `#${scan.id} - ${scan.target}`;
        scanFilter.appendChild(option);
      });
    }
  } catch (error) {
    console.error('Failed to load scans:', error);
  }
}

async function loadStats() {
  try {
    const response = await fetch(`${API_V1}/findings/by-severity`, {
      headers: getHeaders()
    });

    if (!response.ok) return;

    const data = await response.json();
    state.stats = {
      critical: data.critical || 0,
      high: data.high || 0,
      medium: data.medium || 0,
      low: data.low || 0
    };

    updateStatsDisplay();
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
}

function updateStatsDisplay() {
  animateCounter('criticalCount', state.stats.critical);
  animateCounter('highCount', state.stats.high);
  animateCounter('mediumCount', state.stats.medium);
  animateCounter('lowCount', state.stats.low);
}

async function loadFindings() {
  const tbody = document.getElementById('findingsTable');
  tbody.innerHTML = '<tr><td colspan="9" class="text-center"><div class="spinner"></div><p>Loading...</p></td></tr>';

  try {
    const params = new URLSearchParams({
      page: state.currentPage,
      per_page: state.perPage,
      sort_by: state.sortBy,
      sort_order: state.sortOrder
    });

    // Add filters
    if (state.filters.search) params.append('search', state.filters.search);
    if (state.filters.severity.length > 0) {
      state.filters.severity.forEach(s => params.append('severity', s));
    }
    if (state.filters.type.length > 0) {
      state.filters.type.forEach(t => params.append('type', t));
    }
    if (state.filters.status.length > 0) {
      state.filters.status.forEach(s => params.append('status', s));
    }
    if (state.filters.scanId) params.append('scan_run_id', state.filters.scanId);
    if (state.filters.cvssMin !== null) params.append('cvss_min', state.filters.cvssMin);
    if (state.filters.cvssMax !== null) params.append('cvss_max', state.filters.cvssMax);
    if (state.filters.assetType) params.append('asset_type', state.filters.assetType);
    if (state.filters.dateFrom) params.append('date_from', state.filters.dateFrom);
    if (state.filters.dateTo) params.append('date_to', state.filters.dateTo);

    const response = await fetch(`${API_V1}/findings/?${params}`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error('Failed to load findings');

    const data = await response.json();
    state.findings = data.items || [];
    state.totalFindings = data.total || 0;
    state.totalPages = Math.ceil(state.totalFindings / state.perPage);

    renderFindings();
    updatePagination();
  } catch (error) {
    console.error('Failed to load findings:', error);
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger"><p>Failed to load findings: ${escapeHtml(error.message)}</p></td></tr>`;
  }
}

function renderFindings() {
  const tbody = document.getElementById('findingsTable');
  
  if (state.findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="text-center"><div class="empty-state"><p class="text-muted">No findings match your filters</p></div></td></tr>';
    return;
  }

  tbody.innerHTML = state.findings.map(finding => `
    <tr>
      <td>
        <input type="checkbox" 
               class="finding-checkbox" 
               data-id="${finding.id}"
               ${state.selectedFindings.has(finding.id) ? 'checked' : ''}
               onchange="toggleFindingSelection(${finding.id})">
      </td>
      <td><span class="badge badge-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity).toUpperCase()}</span></td>
      <td>
        <a href="#" onclick="viewFinding(${finding.id}); return false;" style="color: var(--text-primary); text-decoration: none;">
          ${escapeHtml(finding.title)}
        </a>
        ${finding.cve_id ? `<br><small class="text-muted">${escapeHtml(finding.cve_id)}</small>` : ''}
      </td>
      <td><span class="badge badge-info">${escapeHtml(finding.finding_type || 'Unknown')}</span></td>
      <td>${renderAssetInfo(finding)}</td>
      <td><strong>${finding.cvss_score?.toFixed(1) || '—'}</strong></td>
      <td>${formatDate(finding.discovered_at)}</td>
      <td><span class="badge badge-status">${finding.status || 'open'}</span></td>
      <td>
        <div class="flex gap-1">
          <button class="btn btn-ghost btn-sm" onclick="viewFinding(${finding.id})" title="View Details">👁️</button>
          <button class="btn btn-ghost btn-sm" onclick="quickRemediate(${finding.id})" title="Remediate">🛠️</button>
        </div>
      </td>
    </tr>
  `).join('');
}

function renderAssetInfo(finding) {
  if (finding.subdomain_id) {
    return `<code>${escapeHtml(finding.subdomain?.name || 'Subdomain')}</code>`;
  } else if (finding.ip_id) {
    return `<code>${escapeHtml(finding.ip?.address || 'IP')}</code>`;
  } else if (finding.service_id) {
    return `<code>${escapeHtml(finding.service?.name || 'Service')}</code>`;
  } else if (finding.webapp_id) {
    return `<code>${escapeHtml(finding.webapp?.url || 'WebApp')}</code>`;
  }
  return '<span class="text-muted">—</span>';
}

// ============================================================================
// FILTERING
// ============================================================================
function applyFilters() {
  // Severity
  const severityFilter = document.getElementById('severityFilter');
  state.filters.severity = Array.from(severityFilter.selectedOptions).map(o => o.value);

  // Type
  const typeFilter = document.getElementById('typeFilter');
  state.filters.type = Array.from(typeFilter.selectedOptions).map(o => o.value);

  // Status
  const statusFilter = document.getElementById('statusFilter');
  state.filters.status = Array.from(statusFilter.selectedOptions).map(o => o.value);

  // Scan
  const scanFilter = document.getElementById('scanFilter');
  state.filters.scanId = scanFilter.value;

  // CVSS Range
  const cvssMin = document.getElementById('cvssMin')?.value;
  const cvssMax = document.getElementById('cvssMax')?.value;
  state.filters.cvssMin = cvssMin ? parseFloat(cvssMin) : null;
  state.filters.cvssMax = cvssMax ? parseFloat(cvssMax) : null;

  // Asset Type
  const assetTypeFilter = document.getElementById('assetTypeFilter');
  state.filters.assetType = assetTypeFilter?.value || '';

  // Date Range
  state.filters.dateFrom = document.getElementById('dateFrom')?.value || null;
  state.filters.dateTo = document.getElementById('dateTo')?.value || null;

  // Reset to page 1
  state.currentPage = 1;

  loadFindings();
  loadStats(); // Refresh stats with filters
}

function clearFilters() {
  state.filters = {
    search: '',
    severity: [],
    type: [],
    status: ['open'],
    scanId: '',
    cvssMin: null,
    cvssMax: null,
    assetType: '',
    dateFrom: null,
    dateTo: null
  };

  // Reset form elements
  document.getElementById('searchInput').value = '';
  document.getElementById('severityFilter').selectedIndex = -1;
  document.getElementById('typeFilter').selectedIndex = -1;
  document.getElementById('statusFilter').selectedIndex = 0; // Select "open"
  document.getElementById('scanFilter').selectedIndex = 0;
  document.getElementById('cvssMin').value = '';
  document.getElementById('cvssMax').value = '';
  document.getElementById('assetTypeFilter').selectedIndex = 0;
  document.getElementById('dateFrom').value = '';
  document.getElementById('dateTo').value = '';

  state.currentPage = 1;
  loadFindings();
  loadStats();
}

function toggleAdvancedFilters() {
  const advanced = document.getElementById('advancedFilters');
  advanced?.classList.toggle('hidden');
}

// ============================================================================
// PAGINATION
// ============================================================================
function updatePagination() {
  const start = (state.currentPage - 1) * state.perPage + 1;
  const end = Math.min(state.currentPage * state.perPage, state.totalFindings);

  document.getElementById('findingsTotal').textContent = state.totalFindings;
  document.getElementById('paginationInfo').textContent = `Showing ${start}-${end} of ${state.totalFindings}`;

  // Update button states
  document.getElementById('firstPageBtn').disabled = state.currentPage === 1;
  document.getElementById('prevPageBtn').disabled = state.currentPage === 1;
  document.getElementById('nextPageBtn').disabled = state.currentPage === state.totalPages;
  document.getElementById('lastPageBtn').disabled = state.currentPage === state.totalPages;

  // Render page numbers
  renderPageNumbers();
}

function renderPageNumbers() {
  const container = document.getElementById('pageNumbers');
  const maxButtons = 5;
  let startPage = Math.max(1, state.currentPage - Math.floor(maxButtons / 2));
  let endPage = Math.min(state.totalPages, startPage + maxButtons - 1);

  if (endPage - startPage < maxButtons - 1) {
    startPage = Math.max(1, endPage - maxButtons + 1);
  }

  const buttons = [];
  for (let i = startPage; i <= endPage; i++) {
    const active = i === state.currentPage ? 'btn-primary' : 'btn-ghost';
    buttons.push(`<button class="btn ${active} btn-sm" onclick="goToPage(${i})">${i}</button>`);
  }

  container.innerHTML = buttons.join('');
}

function goToPage(page) {
  if (page < 1 || page > state.totalPages) return;
  state.currentPage = page;
  loadFindings();
}

function nextPage() {
  goToPage(state.currentPage + 1);
}

function previousPage() {
  goToPage(state.currentPage - 1);
}

function goToLastPage() {
  goToPage(state.totalPages);
}

function changePerPage() {
  const select = document.getElementById('perPageSelect');
  state.perPage = parseInt(select.value);
  state.currentPage = 1;
  loadFindings();
}

// ============================================================================
// SELECTION
// ============================================================================
function toggleFindingSelection(findingId) {
  if (state.selectedFindings.has(findingId)) {
    state.selectedFindings.delete(findingId);
  } else {
    state.selectedFindings.add(findingId);
  }

  updateSelectAllCheckbox();
}

function toggleSelectAll() {
  const checkbox = document.getElementById('selectAllCheck');
  
  if (checkbox.checked) {
    state.findings.forEach(f => state.selectedFindings.add(f.id));
  } else {
    state.selectedFindings.clear();
  }

  // Update individual checkboxes
  document.querySelectorAll('.finding-checkbox').forEach(cb => {
    cb.checked = checkbox.checked;
  });
}

function updateSelectAllCheckbox() {
  const checkbox = document.getElementById('selectAllCheck');
  const visibleIds = state.findings.map(f => f.id);
  const allSelected = visibleIds.every(id => state.selectedFindings.has(id));
  checkbox.checked = allSelected && visibleIds.length > 0;
}

// ============================================================================
// FINDING DETAILS MODAL
// ============================================================================
async function viewFinding(findingId) {
  try {
    const response = await fetch(`${API_V1}/findings/${findingId}`, {
      headers: getHeaders()
    });

    if (!response.ok) throw new Error('Finding not found');

    const finding = await response.json();
    state.currentFinding = finding;

    // Populate modal
    document.getElementById('modalTitle').textContent = finding.title;
    document.getElementById('modalSeverity').textContent = finding.severity.toUpperCase();
    document.getElementById('modalSeverity').className = `badge badge-${finding.severity}`;
    document.getElementById('modalType').textContent = finding.finding_type || 'Unknown';
    document.getElementById('modalStatus').textContent = finding.status || 'open';
    document.getElementById('modalCVSS').textContent = finding.cvss_score?.toFixed(1) || 'N/A';
    document.getElementById('modalVector').textContent = finding.cvss_vector || '—';
    document.getElementById('modalDescription').textContent = finding.description || 'No description available';

    // Asset details
    const assetHtml = [];
    if (finding.subdomain) assetHtml.push(`<strong>Subdomain:</strong> ${escapeHtml(finding.subdomain.name)}`);
    if (finding.ip) assetHtml.push(`<strong>IP:</strong> ${escapeHtml(finding.ip.address)}`);
    if (finding.service) assetHtml.push(`<strong>Service:</strong> ${escapeHtml(finding.service.name)} (Port ${escapeHtml(String(finding.service.port))})`);
    if (finding.webapp) assetHtml.push(`<strong>Web App:</strong> ${escapeHtml(finding.webapp.url)}`);
    document.getElementById('modalAsset').innerHTML = assetHtml.join('<br>') || 'No asset information';

    // References
    if (finding.references && finding.references.length > 0) {
      document.getElementById('modalReferences').classList.remove('hidden');
      document.getElementById('modalReferencesList').innerHTML = finding.references.map(ref => {
        const safeUrl = /^https?:\/\//i.test(ref) ? ref : '#';
        return `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" class="text-primary">${escapeHtml(ref)}</a>`;
      }).join('<br>');
    } else {
      document.getElementById('modalReferences').classList.add('hidden');
    }

    // Evidence
    if (finding.evidence) {
      document.getElementById('modalEvidence').classList.remove('hidden');
      document.getElementById('modalEvidenceContent').textContent = finding.evidence;
    } else {
      document.getElementById('modalEvidence').classList.add('hidden');
    }

    // Remediation
    if (finding.remediation) {
      document.getElementById('modalRemediation').classList.remove('hidden');
      document.getElementById('modalRemediationContent').querySelector('.card-body').innerHTML = 
        `<p>${escapeHtml(finding.remediation)}</p>`;
    } else {
      document.getElementById('modalRemediation').classList.add('hidden');
    }

    // Show modal
    document.getElementById('findingModal').classList.add('active');
  } catch (error) {
    console.error('Failed to load finding:', error);
    alert('Failed to load finding details');
  }
}

function closeModal() {
  document.getElementById('findingModal').classList.remove('active');
  state.currentFinding = null;
}

// ============================================================================
// ACTIONS
// ============================================================================
async function markAsResolved() {
  if (!state.currentFinding) return;

  try {
    const response = await fetch(`${API_V1}/findings/${state.currentFinding.id}`, {
      method: 'PATCH',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: 'resolved' })
    });

    if (!response.ok) throw new Error('Failed to update status');

    closeModal();
    loadFindings();
    loadStats();
  } catch (error) {
    console.error('Failed to mark as resolved:', error);
    alert('Failed to update finding status');
  }
}

async function markAsFalsePositive() {
  if (!state.currentFinding) return;

  if (!confirm('Mark this finding as a false positive?')) return;

  try {
    const response = await fetch(`${API_V1}/findings/${state.currentFinding.id}`, {
      method: 'PATCH',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: 'false_positive' })
    });

    if (!response.ok) throw new Error('Failed to update status');

    closeModal();
    loadFindings();
    loadStats();
  } catch (error) {
    console.error('Failed to mark as false positive:', error);
    alert('Failed to update finding status');
  }
}

async function remediateFinding() {
  if (!state.currentFinding) return;

  try {
    const response = await fetch(`${API_V1}/remediation/remediate`, {
      method: 'POST',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ finding_id: state.currentFinding.id })
    });

    if (!response.ok) throw new Error('Failed to start remediation');

    const data = await response.json();
    alert(`Remediation initiated: ${data.message || 'Success'}`);
    closeModal();
    loadFindings();
  } catch (error) {
    console.error('Failed to remediate:', error);
    alert('Failed to start remediation process');
  }
}

async function quickRemediate(findingId) {
  if (!confirm('Start automated remediation for this finding?')) return;

  try {
    const response = await fetch(`${API_V1}/remediation/remediate`, {
      method: 'POST',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ finding_id: findingId })
    });

    if (!response.ok) throw new Error('Failed to start remediation');

    const data = await response.json();
    alert(`Remediation initiated: ${data.message || 'Success'}`);
    loadFindings();
  } catch (error) {
    console.error('Failed to remediate:', error);
    alert('Failed to start remediation process');
  }
}

function bulkRemediate() {
  if (state.selectedFindings.size === 0) {
    alert('Please select findings to remediate');
    return;
  }

  if (!confirm(`Start remediation for ${state.selectedFindings.size} selected findings?`)) return;

  const promises = Array.from(state.selectedFindings).map(id => 
    fetch(`${API_V1}/remediation/remediate`, {
      method: 'POST',
      headers: {
        ...getHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ finding_id: id })
    })
  );

  Promise.all(promises)
    .then(() => {
      alert('Bulk remediation initiated');
      state.selectedFindings.clear();
      loadFindings();
    })
    .catch(error => {
      console.error('Bulk remediation failed:', error);
      alert('Some remediations failed');
    });
}

function exportFindings() {
  const format = prompt('Export format (csv/json):', 'csv');
  if (!format) return;

  const data = state.findings.map(f => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    type: f.finding_type,
    cvss: f.cvss_score,
    status: f.status,
    discovered: f.discovered_at
  }));

  let content, mimeType, extension;

  if (format === 'json') {
    content = JSON.stringify(data, null, 2);
    mimeType = 'application/json';
    extension = 'json';
  } else {
    // CSV
    const headers = Object.keys(data[0]);
    const rows = data.map(row => headers.map(h => row[h]).join(','));
    content = [headers.join(','), ...rows].join('\n');
    mimeType = 'text/csv';
    extension = 'csv';
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `findings_export_${Date.now()}.${extension}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================================================
// UTILITIES
// ============================================================================
function getHeaders() {
  const apiKey = localStorage.getItem('reconx_api_key') || 'demo_key';
  return {
    'X-API-Key': apiKey
  };
}

function formatDate(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  const now = new Date();
  const diff = now - date;
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));

  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const current = parseInt(el.textContent) || 0;
  if (current === targetValue) return;

  const duration = 300;
  const startTime = performance.now();
  const diff = targetValue - current;

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const value = Math.floor(current + diff * easeOutQuad(progress));
    el.textContent = value;

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = targetValue;
    }
  }

  requestAnimationFrame(update);
}

function easeOutQuad(t) {
  return t * (2 - t);
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeModal();
  }
});
