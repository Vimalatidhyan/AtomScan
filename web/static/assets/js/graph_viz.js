const API_BASE = '/api/v1';

async function api(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(res.statusText || res.status);
  return res.json();
}

async function loadTargets() {
  const sel = document.getElementById('graphTarget');
  try {
    const data = await api('/assets/targets');
    sel.innerHTML = '<option value="">— Select target —</option>';
    (data.targets || []).forEach(t => {
      const opt = document.createElement('option');
      opt.value = t;
      opt.textContent = t;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

document.getElementById('loadGraph').addEventListener('click', async () => {
  const target = document.getElementById('graphTarget').value;
  if (!target) return;
  // Phase 9 not implemented yet; graph data would come from API or static file
  const container = document.getElementById('graphContainer');
  container.innerHTML = `
    <div>
      <p><strong>Graph data not yet available</strong></p>
      <p>Target: ${target}</p>
      <p>After Phase 9 (Attack Graph) is implemented, this view will load <code>graph.json</code> and render nodes/edges (e.g. with D3.js or vis.js).</p>
    </div>
  `;
});

loadTargets();
