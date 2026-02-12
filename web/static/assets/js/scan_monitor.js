const API_BASE = '/api/v1';
let logEventSource = null;
let logPaused = false;

async function api(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(res.statusText || res.status);
  return res.json();
}

function populateScanSelect(targets) {
  const sel = document.getElementById('scanSelect');
  const first = sel.options[0];
  sel.innerHTML = '';
  sel.appendChild(first);
  (targets || []).forEach(t => {
    const opt = document.createElement('option');
    opt.value = 'target_' + t;
    opt.textContent = t + ' (target)';
    sel.appendChild(opt);
  });
}

async function loadTargetsForSelect() {
  try {
    const data = await api('/assets/targets');
    populateScanSelect(data.targets || []);
  } catch (_) {}
}

function showStatus(data) {
  const card = document.getElementById('statusCard');
  const err = document.getElementById('statusError');
  card.classList.remove('hidden');
  err.classList.add('hidden');
  document.getElementById('statusValue').textContent = data.status || '—';
  document.getElementById('progressValue').textContent = data.progress ?? 0;
  document.getElementById('targetValue').textContent = data.target || '—';
  document.getElementById('startedValue').textContent = data.started_at
    ? new Date(data.started_at).toLocaleString()
    : '—';
}

async function refreshStatus() {
  const sel = document.getElementById('scanSelect');
  const input = document.getElementById('scanIdInput');
  const scanId = (input && input.value.trim()) || (sel && sel.value) || '';
  if (!scanId) return;
  try {
    const data = await api('/scans/' + encodeURIComponent(scanId) + '/status');
    showStatus(data);
  } catch (e) {
    document.getElementById('statusCard').classList.remove('hidden');
    document.getElementById('statusError').textContent = e.message || 'Failed to load status';
    document.getElementById('statusError').classList.remove('hidden');
  }
}

document.getElementById('refreshStatus').addEventListener('click', refreshStatus);

document.getElementById('scanSelect').addEventListener('change', function () {
  document.getElementById('scanIdInput').value = this.value || '';
  if (this.value) refreshStatus();
});

document.getElementById('scanIdInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') refreshStatus();
});

function connectLogStream() {
  if (logEventSource) return;
  const stream = document.getElementById('logStream');
  stream.innerHTML = '<div class="line">Connecting to log stream…</div>';
  const url = API_BASE + '/stream/logs/live';
  logEventSource = new EventSource(url);
  logEventSource.onmessage = function (ev) {
    if (logPaused) return;
    try {
      const data = JSON.parse(ev.data);
      const line = document.createElement('div');
      line.className = 'line';
      line.textContent = data.line || ev.data;
      stream.appendChild(line);
      stream.scrollTop = stream.scrollHeight;
    } catch (_) {
      const line = document.createElement('div');
      line.className = 'line';
      line.textContent = ev.data;
      stream.appendChild(line);
      stream.scrollTop = stream.scrollHeight;
    }
  };
  logEventSource.onerror = function () {
    stream.appendChild(document.createElement('div')).textContent = '[Stream disconnected]';
  };
}

document.getElementById('toggleLog').addEventListener('click', function () {
  logPaused = !logPaused;
  this.textContent = logPaused ? 'Resume stream' : 'Pause stream';
});

loadTargetsForSelect();
connectLogStream();
