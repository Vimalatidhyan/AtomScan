/**
 * output-ui-binder.js  -  Dynamic Output File -> UI Data Binding
 *
 * Calls /api/assessment/{scanId}/... endpoints and renders data into
 * the existing scan_viewer_v2 panels, dynamically injecting new panels
 * for modules that don't have pre-built HTML placeholders.
 *
 * Existing panels (already in HTML):
 *   liveHostsPanel, asnPanel, whoisPanel, dnsPanel,
 *   cloudPanel, ctPanel, assetsPanel, logPanel
 *
 * Injected panels (created by this script before #logPanel):
 *   subdomains, directories, urls, javascript, api-discovery,
 *   secrets, ports, vulnerabilities, ssl, threatintel,
 *   compliance, attackgraph, change-detection
 */

(function () {
  'use strict';

  /* --- Config ------------------------------------------------- */
  const BASE   = '/api/assessment';
  const TIMEOUT = 30000;

  /* --- SVG helper --------------------------------------------- */
  function svgPath(d) {
    return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="' + d + '"/></svg>';
  }

  /* --- Panel definitions (injected before #logPanel) ---------- */
  const PANELS = [
    { key:'subdomains',      id:'obSubdomainsPanel',  icon:svgPath('M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3'), title:'Subdomains',          badgeId:'obSubdomainsBadge' },
    { key:'directories',     id:'obDirsPanel',        icon:svgPath('M3 7h18M3 12h18M3 17h18'),                                                          title:'Directory Bruteforce', badgeId:'obDirsBadge'       },
    { key:'urls',            id:'obUrlsPanel',        icon:svgPath('M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101'),            title:'URL Collection',       badgeId:'obUrlsBadge'       },
    { key:'javascript',      id:'obJsPanel',          icon:svgPath('M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4'),                                            title:'JavaScript Files',     badgeId:'obJsBadge'         },
    { key:'api-discovery',   id:'obApiPanel',         icon:svgPath('M8 9l3 3-3 3m5 0h3'),                                                               title:'API Discovery',        badgeId:'obApiBadge'        },
    { key:'secrets',         id:'obSecretsPanel',     icon:svgPath('M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z'), title:'Secrets & Leaks', badgeId:'obSecretsBadge' },
    { key:'ports',           id:'obPortsPanel',       icon:svgPath('M5 12h14M12 5l7 7-7 7'),                                                            title:'Port Scanning',        badgeId:'obPortsBadge'      },
    { key:'vulnerabilities', id:'obVulnsPanel',       icon:svgPath('M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z'), title:'Vulnerabilities', badgeId:'obVulnsBadge' },
    { key:'ssl',             id:'obSslPanel',         icon:svgPath('M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'), title:'SSL / TLS', badgeId:'obSslBadge' },
    { key:'threatintel',     id:'obThreatPanel',      icon:svgPath('M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'),                        title:'Threat Intelligence',  badgeId:'obThreatBadge'     },
    { key:'compliance',      id:'obCompPanel',        icon:svgPath('M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2'), title:'Compliance', badgeId:'obCompBadge' },
    { key:'attackgraph',     id:'obAttackPanel',      icon:svgPath('M13 10V3L4 14h7v7l9-11h-7z'),                                                        title:'Attack Graph',         badgeId:'obAttackBadge'     },
    { key:'change-detection',id:'obChangePanel',      icon:svgPath('M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15'), title:'Change Detection', badgeId:'obChangeBadge' },
  ];

  /* --- Utilities ---------------------------------------------- */
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function setBadge(id, count) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = count >= 1000 ? (count/1000).toFixed(1)+'k' : count;
    el.style.display = count > 0 ? '' : 'none';
  }
  function setStat(id, val) { var el=document.getElementById(id); if(el) el.textContent=val; }
  function setBody(id, html) { var el=document.getElementById(id); if(el) el.innerHTML=html; }

  async function apiFetch(url) {
    var controller = new AbortController();
    var timer = setTimeout(function(){ controller.abort(); }, TIMEOUT);
    try {
      var res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) return null;
      return res.json();
    } catch(e) { clearTimeout(timer); return null; }
  }

  function mkTable(cols, rows, emptyMsg) {
    if (!rows || !rows.length) return '<div class="tm-empty" style="padding:.75rem 1rem">'+(emptyMsg||'No data')+'</div>';
    var head = '<tr>' + cols.map(function(c){ return '<th style="padding:.4rem .6rem;white-space:nowrap;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted,#888)">'+esc(c)+'</th>'; }).join('') + '</tr>';
    var body = rows.map(function(row){
      var cells = (Array.isArray(row) ? row : cols.map(function(c){ return row[c]??''; }))
        .map(function(v){ return '<td style="padding:.35rem .6rem;font-size:.8rem">'+esc(String(v==null?'':v))+'</td>'; }).join('');
      return '<tr>'+cells+'</tr>';
    }).join('');
    return '<style>.ob-tbl{width:100%;border-collapse:collapse}.ob-tbl tr:nth-child(even){background:rgba(0,0,0,.03)}.ob-tbl td,.ob-tbl th{border-bottom:1px solid var(--border,#e5e7eb)}</style>'
      + '<table class="ob-tbl"><thead>'+head+'</thead><tbody>'+body+'</tbody></table>';
  }

  function listBox(items, emptyMsg) {
    if (!items||!items.length) return '<div class="tm-empty">'+(emptyMsg||'No data')+'</div>';
    return '<div style="font-size:.8rem;line-height:1.8;padding:.5rem .75rem;column-count:auto;column-width:260px">'
      + items.map(function(v){ return '<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(String(v))+'</div>'; }).join('')
      + '</div>';
  }

  /* --- Panel injection --------------------------------------- */
  function ensurePanel(cfg) {
    if (document.getElementById(cfg.id)) return;
    var logPanel = document.getElementById('logPanel');
    if (!logPanel) return;
    var el = document.createElement('div');
    el.className = 'tm-panel mt-3';
    el.id = cfg.id;
    el.innerHTML = '<div class="tm-panel-header" onclick="tmTogglePanel(\''+cfg.id+'\')"><span class="tm-panel-icon">'+cfg.icon+'</span><span class="tm-panel-title">'+cfg.title+'</span><span class="tm-badge" id="'+cfg.badgeId+'" style="display:none">0</span><span class="tm-panel-spacer"></span><span class="tm-chevron" id="'+cfg.id+'Chevron">&#9662;</span></div><div class="tm-panel-body" id="'+cfg.id+'Body"><div class="tm-empty">Loading...</div></div>';
    logPanel.parentNode.insertBefore(el, logPanel);
  }

  /* --- Renderers --------------------------------------------- */
  function renderSubdomains(d, bodyId, badgeId) {
    var subs = d.subdomains||[];
    setBadge(badgeId, d.total||subs.length);
    setStat('detailSubs', d.total||subs.length);
    setBody(bodyId, listBox(subs,'No subdomains found in output files'));
  }

  function renderDirectories(d, bodyId, badgeId) {
    var tools = d.tools||{}, total = d.total_findings||0;
    setBadge(badgeId, total);
    if (!total) { setBody(bodyId,'<div class="tm-empty">No directory bruteforce results found</div>'); return; }
    var html='';
    Object.keys(tools).forEach(function(fn){
      var findings=tools[fn];
      var rows=findings.map(function(f){
        if(typeof f==='string') return {Status:'',URL:f,Size:''};
        return {Status:f.status||f['status-code']||'',URL:f.url||f.input||f.redirectlocation||String(f),Size:f.length||f.size||''};
      });
      html+='<div style="font-size:.7rem;font-weight:700;padding:.35rem .75rem;background:var(--bg-body,#f8f9fa);border-bottom:1px solid var(--border,#e5e7eb)">'+esc(fn)+' ('+findings.length+')</div>';
      html+=mkTable(['Status','URL','Size'],rows.slice(0,200),'No findings');
    });
    setBody(bodyId,html);
  }

  function renderUrls(d, bodyId, badgeId) {
    setBadge(badgeId, d.total||0);
    if (!(d.total)) { setBody(bodyId,'<div class="tm-empty">No URL collection results found</div>'); return; }
    var srcRows=Object.keys(d.sources||{}).map(function(t){ return {Tool:t,Count:(d.sources||{})[t]}; });
    setBody(bodyId,
      '<div style="padding:.5rem .75rem"><strong>Sources:</strong></div>'+mkTable(['Tool','Count'],srcRows,'')+
      '<div style="padding:.5rem .75rem;font-weight:700;font-size:.75rem">Sample URLs</div>'+listBox((d.sample||[]).slice(0,300),'No URLs'));
  }

  function renderJavascript(d, bodyId, badgeId) {
    setBadge(badgeId, d.total_js||0);
    var html=listBox(d.js_files||[],'No JavaScript files found');
    if (d.total_secrets>0) html+='<div style="padding:.5rem .75rem;font-weight:700;color:var(--danger,#dc2626)">Secrets Found ('+d.total_secrets+')</div>'+listBox(d.secrets||[]);
    setBody(bodyId,html);
  }

  function renderApiDiscovery(d, bodyId, badgeId) {
    var eps=d.endpoints||[];
    setBadge(badgeId, d.total||eps.length);
    var rows=eps.map(function(ep){ return {URL:ep.url||'',Method:ep.method||'',Params:Array.isArray(ep.params)?ep.params.join(', '):String(ep.params||'')}; });
    setBody(bodyId, mkTable(['URL','Method','Params'],rows,'No API endpoints discovered'));
  }

  function renderSecrets(d, bodyId, badgeId) {
    var findings=d.findings||[];
    setBadge(badgeId, d.total||findings.length);
    if(!findings.length){ setBody(bodyId,'<div class="tm-empty">No secrets or leaks found</div>'); return; }
    var rows=findings.map(function(f){ return {Source:f._source||'',Type:f.RuleID||f.Description||f.rule||f.detector_type||'',Match:f.Secret||f.secret||f.match||f.line||'',File:f.File||f.file||''}; });
    setBody(bodyId, mkTable(['Source','Type','Match','File'],rows,''));
  }

  function renderPorts(d, bodyId, badgeId) {
    var hosts=d.hosts||[];
    setBadge(badgeId, d.host_count||hosts.length||d.total_lines||0);
    setStat('detailPorts', d.open_ports||0);
    if(d.raw_lines){ setBody(bodyId,listBox(d.raw_lines,'No port data')); return; }
    if(!hosts.length){ setBody(bodyId,'<div class="tm-empty">No port scan data found</div>'); return; }
    var html='';
    hosts.slice(0,100).forEach(function(host){
      var portRows=(host.ports||[]).map(function(p){ return {Port:p.portid+'/'+p.protocol,State:p.state,Service:p.service||'',Product:((p.product||'')+' '+(p.version||'')).trim()}; });
      html+='<div style="font-size:.75rem;font-weight:700;padding:.35rem .75rem;background:var(--bg-body,#f8f9fa);border-bottom:1px solid var(--border)">'+esc(host.ip)+' '+(host.hostname?'('+esc(host.hostname)+')':'')+'</div>';
      html+=mkTable(['Port','State','Service','Product'],portRows,'No open ports');
    });
    setBody(bodyId, html||'<div class="tm-empty">No hosts</div>');
  }

  function renderVulnerabilities(d, bodyId, badgeId) {
    var findings=d.findings||[], total=d.total||findings.length;
    setBadge(badgeId, total);
    setStat('detailVulns', total);
    var crits=findings.filter(function(f){ return /critical/i.test(f.severity||f.risk||''); }).length;
    setStat('detailCritical', crits);
    if(!findings.length){ setBody(bodyId,'<div class="tm-empty">No vulnerability findings in output files</div>'); return; }
    var rows=findings.map(function(f){ return {Tool:f._tool||'',Severity:f.severity||f.risk||'',Description:(f.description||f.msg||f.message||f.line||'').toString().substring(0,120),Target:f.url||f.host||f._target||''}; });
    setBody(bodyId, mkTable(['Tool','Severity','Description','Target'],rows,''));
  }

  function renderSsl(d, bodyId, badgeId) {
    var results=d.results||[];
    setBadge(badgeId, d.total||results.length);
    if(!results.length){ setBody(bodyId,'<div class="tm-empty">No SSL/TLS scan data found</div>'); return; }
    var html='';
    results.slice(0,20).forEach(function(r){
      var rows=Object.entries(r.data||{}).slice(0,30).map(function(kv){ return [kv[0], (typeof kv[1]==='object'?JSON.stringify(kv[1]).substring(0,100):String(kv[1]))]; });
      html+='<div style="font-size:.75rem;font-weight:700;padding:.35rem .75rem;background:var(--bg-body);border-bottom:1px solid var(--border)">'+esc(r.target||'')+'</div>';
      html+=mkTable(['Key','Value'],rows,'No data');
    });
    setBody(bodyId, html||'<div class="tm-empty">No TLS results</div>');
  }

  function renderThreatIntel(d, bodyId, badgeId) {
    var hits=d.blocklist_hits||[];
    setBadge(badgeId, d.total_hits||hits.length);
    var html='';
    var sumEntries=Object.entries(d.summary||{});
    if(sumEntries.length) html+=mkTable(['Metric','Value'],sumEntries.slice(0,20).map(function(kv){ return [kv[0],(typeof kv[1]==='object'?JSON.stringify(kv[1]).substring(0,100):String(kv[1]))]; }),'');
    if(hits.length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem">Blocklist Hits ('+hits.length+')</div>'+mkTable(Object.keys(hits[0]||{IP:'',Source:''}),hits.slice(0,100),'');
    if(!html) html='<div class="tm-empty">No threat intelligence data found</div>';
    setBody(bodyId, html);
  }

  function renderCompliance(d, bodyId, badgeId) {
    var frameworks=d.frameworks||{};
    setBadge(badgeId, Object.keys(frameworks).length);
    var html='';
    var sumEntries=Object.entries(d.summary||{});
    if(sumEntries.length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem">Summary</div>'+mkTable(['Metric','Value'],sumEntries.slice(0,20).map(function(kv){ return [kv[0],(typeof kv[1]==='object'?JSON.stringify(kv[1]).substring(0,100):String(kv[1]))]; }),'');
    Object.keys(frameworks).forEach(function(fw){
      html+='<div style="font-size:.75rem;font-weight:700;padding:.35rem .75rem;background:var(--bg-body);border-bottom:1px solid var(--border)">'+esc(fw.toUpperCase())+'</div>';
      html+=listBox(frameworks[fw],'No data');
    });
    if(!html) html='<div class="tm-empty">No compliance data found</div>';
    setBody(bodyId, html);
  }

  function renderAttackGraph(d, bodyId, badgeId) {
    var nodeCount=d.node_count||0;
    setBadge(badgeId, nodeCount);
    var html='';
    var riskEntries=Object.entries(d.risk||{});
    if(riskEntries.length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem">Risk Summary</div>'+mkTable(['Metric','Value'],riskEntries.slice(0,20).map(function(kv){ return [kv[0],(typeof kv[1]==='object'?JSON.stringify(kv[1]).substring(0,100):String(kv[1]))]; }),'');
    if(nodeCount) html+='<div style="padding:.35rem .75rem;font-size:.8rem">Nodes: <strong>'+nodeCount+'</strong> &nbsp; Edges: <strong>'+(d.edge_count||0)+'</strong> &nbsp; Paths: <strong>'+((d.paths||[]).length)+'</strong></div>';
    if(!html) html='<div class="tm-empty">No attack graph data found</div>';
    setBody(bodyId, html);
  }

  function renderChangeDetection(d, bodyId, badgeId) {
    var alerts=d.alerts||[];
    setBadge(badgeId, alerts.length);
    var html='';
    if(alerts.length){
      var rows=alerts.slice(0,100).map(function(a){ return typeof a==='string'?{Alert:a,Type:'',Severity:''}:{Alert:(a.message||a.description||a.alert||JSON.stringify(a).substring(0,80)),Type:a.type||'',Severity:a.severity||''}; });
      html+=mkTable(['Alert','Type','Severity'],rows,'');
    }
    var deltaEntries=Object.entries(d.delta||{});
    if(deltaEntries.length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem;margin-top:.5rem">Delta</div>'+mkTable(['Key','Value'],deltaEntries.slice(0,30).map(function(kv){ return [kv[0],JSON.stringify(kv[1]).substring(0,80)]; }),'');
    if(!html) html='<div class="tm-empty">No change detection data found</div>';
    setBody(bodyId, html);
  }

  /* --- Existing panel enrichers (don't replace if already populated) --- */
  function enrichLiveHosts(d) {
    var hosts=d.hosts||[], count=d.total||hosts.length;
    if(!count) return;
    setBadge('liveHostsBadge', count);
    setStat('detailLiveHosts', count);
    var existing=document.getElementById('liveHostsPanelBody');
    if(!existing||existing.children.length>1) return;
    var isObj=hosts.length&&typeof hosts[0]==='object';
    if(!isObj) return;
    var cols=['url','status_code','content_length','title','tech'];
    var rows=hosts.slice(0,500).map(function(h){ return cols.map(function(c){ var v=h[c]??''; return Array.isArray(v)?v.join(', '):String(v); }); });
    existing.innerHTML=mkTable(cols.map(function(c){ return c.replace('_',' '); }),rows,'No alive hosts found');
  }

  function enrichAsn(d) {
    var count=d.cidr_count||(d.cidrs||[]).length;
    if(!count) return;
    setBadge('asnCidrBadge', count);
    var existing=document.getElementById('asnPanelBody');
    if(!existing||existing.children.length>1) return;
    var html='';
    if((d.cidrs||[]).length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem">CIDRs ('+d.cidrs.length+')</div>'+mkTable(['CIDR'],d.cidrs.slice(0,300).map(function(c){ return {CIDR:c}; }),'');
    if((d.ips||[]).length) html+='<div style="padding:.35rem .75rem;font-weight:700;font-size:.75rem">IPs ('+d.ips.length+')</div>'+mkTable(['IP'],d.ips.slice(0,300).map(function(ip){ return {IP:ip}; }),'');
    if(!html) html='<div class="tm-empty">No ASN data</div>';
    existing.innerHTML=html;
  }

  function enrichWhois(d) {
    var fields=d.fields||{};
    var existing=document.getElementById('whoisPanelBody');
    var badge=document.getElementById('whoisBadge');
    if(!Object.keys(fields).length||!existing||existing.children.length>1) return;
    if(badge){ badge.textContent='✓'; badge.style.display=''; }
    var rows=Object.entries(fields).slice(0,40).map(function(kv){ return {Field:kv[0],Value:kv[1]}; });
    existing.innerHTML=mkTable(['Field','Value'],rows,'No WHOIS data');
  }

  function enrichCloud(d) {
    var total=d.total||0;
    if(!total) return;
    setBadge('cloudBadge', total);
    setStat('detailCloudAssets', total);
    var existing=document.getElementById('cloudPanelBody');
    if(!existing||existing.children.length>1) return;
    existing.innerHTML=mkTable(['Asset'],(d.assets||[]).slice(0,300).map(function(a){ return {Asset:a}; }),'No cloud assets found');
  }

  function enrichCt(d) {
    var total=d.total||0;
    if(!total) return;
    setBadge('ctBadge', total);
    var existing=document.getElementById('ctPanelBody');
    if(!existing||existing.children.length>1) return;
    existing.innerHTML=listBox((d.domains||[]).slice(0,500),'No CT domains found');
  }

  /* --- Main orchestrator -------------------------------------- */
  async function bind(scanId) {
    if (!scanId) return;
    PANELS.forEach(ensurePanel);

    var id = encodeURIComponent(scanId);
    function url(path){ return BASE+'/'+id+'/'+path; }

    var results = await Promise.all([
      apiFetch(url('alive')),          // 0
      apiFetch(url('asn')),            // 1
      apiFetch(url('whois')),          // 2
      apiFetch(url('cloud')),          // 3
      apiFetch(url('certificates')),   // 4
      apiFetch(url('subdomains')),     // 5
      apiFetch(url('directories')),    // 6
      apiFetch(url('urls')),           // 7
      apiFetch(url('javascript')),     // 8
      apiFetch(url('api-discovery')),  // 9
      apiFetch(url('secrets')),        // 10
      apiFetch(url('ports')),          // 11
      apiFetch(url('vulnerabilities')),// 12
      apiFetch(url('ssl')),            // 13
      apiFetch(url('threatintel')),    // 14
      apiFetch(url('compliance')),     // 15
      apiFetch(url('attackgraph')),    // 16
      apiFetch(url('change-detection')),// 17
    ]);

    function cfg(key){ return PANELS.find(function(p){ return p.key===key; })||{}; }

    if (results[0])  enrichLiveHosts(results[0]);
    if (results[1])  enrichAsn(results[1]);
    if (results[2])  enrichWhois(results[2]);
    if (results[3])  enrichCloud(results[3]);
    if (results[4])  enrichCt(results[4]);
    if (results[5])  { var c=cfg('subdomains');      renderSubdomains(results[5],      c.id+'Body', c.badgeId); }
    if (results[6])  { var c=cfg('directories');     renderDirectories(results[6],     c.id+'Body', c.badgeId); }
    if (results[7])  { var c=cfg('urls');             renderUrls(results[7],           c.id+'Body', c.badgeId); }
    if (results[8])  { var c=cfg('javascript');      renderJavascript(results[8],      c.id+'Body', c.badgeId); }
    if (results[9])  { var c=cfg('api-discovery');   renderApiDiscovery(results[9],    c.id+'Body', c.badgeId); }
    if (results[10]) { var c=cfg('secrets');          renderSecrets(results[10],        c.id+'Body', c.badgeId); }
    if (results[11]) { var c=cfg('ports');            renderPorts(results[11],          c.id+'Body', c.badgeId); }
    if (results[12]) { var c=cfg('vulnerabilities'); renderVulnerabilities(results[12], c.id+'Body', c.badgeId); }
    if (results[13]) { var c=cfg('ssl');              renderSsl(results[13],            c.id+'Body', c.badgeId); }
    if (results[14]) { var c=cfg('threatintel');     renderThreatIntel(results[14],    c.id+'Body', c.badgeId); }
    if (results[15]) { var c=cfg('compliance');      renderCompliance(results[15],     c.id+'Body', c.badgeId); }
    if (results[16]) { var c=cfg('attackgraph');     renderAttackGraph(results[16],    c.id+'Body', c.badgeId); }
    if (results[17]) { var c=cfg('change-detection');renderChangeDetection(results[17],c.id+'Body', c.badgeId); }
  }

  /* --- Public API --------------------------------------------- */
  window.OutputBinder      = { bind: bind };
  window.initOutputBinding = function(scanId) { bind(scanId).catch(console.error); };

})();