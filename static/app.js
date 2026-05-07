// ── State ────────────────────────────────────────────────────────────────────
let G = { data: null, apiKey: localStorage.getItem('ir_apikey') || '' };

window.onload = () => {
  if (G.apiKey) document.getElementById('api-key-input').value = G.apiKey;
  document.getElementById('hist-key').value = G.apiKey;
};

// ── Navigation ───────────────────────────────────────────────────────────────
function showPage(id, el) {
  document.querySelectorAll('[id^="page-"]').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).style.display = 'block';
  if (el) el.classList.add('active');
}

function switchTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.getElementById('pane-' + id.replace('tab-', '')).classList.add('active');
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = (type === 'ok' ? '✅ ' : '❌ ') + msg;
  el.className = 'show ' + type;
  setTimeout(() => el.className = '', 3500);
}

// ── Save API key ──────────────────────────────────────────────────────────────
function saveKey() {
  G.apiKey = document.getElementById('api-key-input').value.trim();
  localStorage.setItem('ir_apikey', G.apiKey);
  document.getElementById('hist-key').value = G.apiKey;
  toast('Đã lưu API key');
}

function getKey() {
  return document.getElementById('api-key-input').value.trim() || G.apiKey;
}

// ── Loading helpers ───────────────────────────────────────────────────────────
function showLoading(msg = 'Đang phân tích...') {
  document.getElementById('analyze-loading').style.display = 'block';
  document.getElementById('loading-msg').textContent = msg;
}
function hideLoading() {
  document.getElementById('analyze-loading').style.display = 'none';
}

// ── API calls ─────────────────────────────────────────────────────────────────
async function runDemo(malware = 'emotet') {
  showPage('analyze', document.querySelector('[data-page=analyze]'));
  showLoading(`Đang tải dữ liệu demo ${malware.toUpperCase()}...`);
  try {
    const r = await fetch(`/api/demo/${malware}`);
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAll(j.data);
    showPage('home', document.querySelector('[data-page=home]'));
    toast(`Demo ${malware.toUpperCase()} đã tải xong!`);
  } catch (e) { toast(e.message, 'err'); }
  finally { hideLoading(); }
}

async function analyzeTask() {
  const key = getKey(), uuid = document.getElementById('task-uuid').value.trim();
  if (!key)  return toast('Nhập API key trước', 'err');
  if (!uuid) return toast('Nhập Task UUID', 'err');
  showLoading('Đang lấy dữ liệu từ Any.Run...');
  try {
    const r = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key, task_id: uuid })
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAll(j.data);
    showPage('home', document.querySelector('[data-page=home]'));
    toast('Phân tích hoàn tất!');
  } catch (e) { toast(e.message, 'err'); }
  finally { hideLoading(); }
}

// Submit URL chỉ lấy UUID
async function submitURLOnly() {
  const key = getKey(), url = document.getElementById('submit-url').value.trim();
  if (!key) return toast('Nhập API key trước', 'err');
  if (!url) return toast('Nhập URL', 'err');
  document.getElementById('url-result').innerHTML = '<div style="color:var(--text2);font-size:13px">Đang submit...</div>';
  try {
    const r = await fetch('/api/submit/url', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({api_key:key, url}) });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    document.getElementById('url-result').innerHTML =
      `<div style="color:var(--green);font-size:13px">✅ Đã submit!<br>
       <span style="color:var(--text2)">Task UUID (dán vào tab Task UUID sau 1-3 phút):</span><br>
       <code style="color:var(--accent);cursor:pointer" onclick="copyText('${j.task_id}')">${j.task_id}</code></div>`;
    toast('Đã submit URL!');
  } catch(e) { toast(e.message, 'err'); }
}

// Submit URL → tự chờ → tự phân tích (như main.py --url)
async function submitAnalyzeURL() {
  const key = getKey(), url = document.getElementById('submit-url').value.trim();
  if (!key) return toast('Nhập API key trước', 'err');
  if (!url) return toast('Nhập URL', 'err');
  document.getElementById('url-result').innerHTML = '';
  try {
    const r = await fetch('/api/submit_analyze/url', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({api_key:key, url}) });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    toast('Đã submit! Đang chờ sandbox...');
    startPolling(j.task_id);
  } catch(e) { toast(e.message, 'err'); }
}

// Submit File chỉ lấy UUID
async function submitFileOnly() {
  const key = getKey();
  if (!key) return toast('Nhập API key trước', 'err');
  if (!selectedFile) return toast('Chọn file trước', 'err');
  const fd = new FormData();
  fd.append('api_key', key);
  fd.append('file', selectedFile);
  document.getElementById('file-result').innerHTML = '<div style="color:var(--text2);font-size:13px">Đang upload...</div>';
  try {
    const r = await fetch('/api/submit/file', { method:'POST', body:fd });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    document.getElementById('file-result').innerHTML =
      `<div style="color:var(--green);font-size:13px">✅ Đã submit!<br>
       <code style="color:var(--accent);cursor:pointer" onclick="copyText('${j.task_id}')">${j.task_id}</code></div>`;
    toast('Đã submit file!');
  } catch(e) { toast(e.message, 'err'); }
}

// Submit File → tự chờ → tự phân tích (như main.py --file)
async function submitAnalyzeFile() {
  const key = getKey();
  if (!key) return toast('Nhập API key trước', 'err');
  if (!selectedFile) return toast('Chọn file trước', 'err');
  const fd = new FormData();
  fd.append('api_key', key);
  fd.append('file', selectedFile);
  document.getElementById('file-result').innerHTML = '';
  try {
    const r = await fetch('/api/submit_analyze/file', { method:'POST', body:fd });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    toast('Đã submit! Đang chờ sandbox...');
    startPolling(j.task_id);
  } catch(e) { toast(e.message, 'err'); }
}

// Polling progress bar (dùng cho submit_analyze)
let _pollTimer = null;
function startPolling(task_id) {
  showPage('analyze', document.querySelector('[data-page=analyze]'));
  document.getElementById('progress-panel').style.display = 'block';
  document.getElementById('progress-task').textContent = task_id;
  document.getElementById('progress-bar').style.width = '5%';
  document.getElementById('progress-pct').textContent = '5%';
  document.getElementById('progress-msg').textContent = 'Đã submit lên Any.Run sandbox...';
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {
    try {
      const r = await fetch(`/api/task_status/${task_id}`);
      const j = await r.json();
      if (!j.ok) { clearInterval(_pollTimer); return; }
      document.getElementById('progress-bar').style.width = j.progress + '%';
      document.getElementById('progress-pct').textContent = j.progress + '%';
      document.getElementById('progress-msg').textContent = j.message;
      if (j.status === 'done') {
        clearInterval(_pollTimer);
        document.getElementById('progress-panel').style.display = 'none';
        renderAll(j.data);
        showPage('home', document.querySelector('[data-page=home]'));
        toast('Phân tích hoàn tất!');
      } else if (j.status === 'error') {
        clearInterval(_pollTimer);
        document.getElementById('progress-panel').style.display = 'none';
        toast('Lỗi: ' + j.message, 'err');
      }
    } catch(e) { /* mạng tạm lỗi, thử lại */ }
  }, 5000);
}

// Mở thư mục reports
async function openReports() {
  await fetch('/api/open_reports');
  toast('Đã mở thư mục reports!');
}

let selectedFile = null;
function handleFileSelect(inp) {
  selectedFile = inp.files[0];
  if (selectedFile) document.getElementById('file-name').textContent = '📄 ' + selectedFile.name;
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('dragover');
  selectedFile = e.dataTransfer.files[0];
  if (selectedFile) document.getElementById('file-name').textContent = '📄 ' + selectedFile.name;
}


async function loadHistory() {
  const key = document.getElementById('hist-key').value.trim() || getKey();
  if (!key) return toast('Nhập API key', 'err');
  document.getElementById('history-content').innerHTML = '<div class="loading-wrap"><div class="spinner"></div><p>Đang tải lịch sử...</p></div>';
  try {
    const r = await fetch('/api/history', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key })
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderHistory(j.tasks);
  } catch (e) {
    document.getElementById('history-content').innerHTML = `<div class="card"><span style="color:var(--red)">${e.message}</span></div>`;
    toast(e.message, 'err');
  }
}

// ── Render functions ──────────────────────────────────────────────────────────
function renderAll(data) {
  G.data = data;
  renderDashboard(data);
  renderPlaybook(data);
  renderIOCs(data);
}

function severityClass(lvl) {
  if (lvl >= 3) return 'critical';
  if (lvl === 2) return 'high';
  if (lvl === 1) return 'medium';
  return 'clean';
}
function severityColor(lvl) {
  const m = { critical:'var(--red)', high:'var(--orange)', medium:'var(--yellow)', clean:'var(--green)' };
  return m[severityClass(lvl)] || 'var(--text2)';
}

function renderDashboard(d) {
  document.getElementById('welcome-screen').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  const t = d.threat, p = d.playbook, net = d.network, pr = d.processes;
  const lvl = t.threat_level;

  // Stats
  document.getElementById('stat-row').innerHTML = `
    <div class="stat-box"><div class="val" style="color:${severityColor(lvl)}">${lvl}/4</div><div class="lbl">Threat Level</div></div>
    <div class="stat-box"><div class="val" style="color:var(--accent)">${t.mitre.length}</div><div class="lbl">MITRE Techniques</div></div>
    <div class="stat-box"><div class="val" style="color:var(--red)">${net.ips.length + net.domains.length}</div><div class="lbl">C2 Indicators</div></div>
  `;

  // Threat card
  const bar_w = Math.round((lvl / 4) * 100);
  document.getElementById('card-threat').innerHTML = `
    <div class="card-title">⚠️ Threat Assessment</div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <span class="badge ${severityClass(lvl)}">${p.severity}</span>
      <span style="font-size:22px;font-weight:700;color:${severityColor(lvl)}">${t.verdict}</span>
    </div>
    <div style="font-size:15px;font-weight:600;margin-bottom:4px">${t.threat_name || 'Unknown Malware'}</div>
    <div style="margin-bottom:12px">${t.tags.map(g=>`<span style="background:rgba(0,212,255,0.1);color:var(--accent);font-size:11px;padding:2px 8px;border-radius:4px;margin-right:4px">${g}</span>`).join('')}</div>
    <div class="threat-bar-wrap">
      <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text2);margin-bottom:4px"><span>Mức độ nguy hiểm</span><span>${lvl}/4</span></div>
      <div class="threat-bar"><div class="threat-bar-fill" style="width:${bar_w}%;background:${severityColor(lvl)}"></div></div>
    </div>
    <div style="margin-top:14px;font-size:13px;color:var(--text2)">
      🖥️ ${d.os_env} &nbsp;|&nbsp; ⏱️ ${d.duration}s &nbsp;|&nbsp;
      <a href="${d.analysis_url}" target="_blank" style="color:var(--accent)">Xem trên Any.Run ↗</a>
    </div>`;

  // File card
  const f = d.file;
  document.getElementById('card-file').innerHTML = f ? `
    <div class="card-title">📄 Thông tin File</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:12px;word-break:break-all">${f.name}</div>
    <div style="font-size:13px;color:var(--text2);margin-bottom:8px">${f.type} &nbsp;|&nbsp; ${(f.size/1024).toFixed(1)} KB</div>
    <div style="margin-top:12px">
      <div style="font-size:11px;color:var(--text2);margin-bottom:3px">MD5</div>
      <div class="mono" style="font-size:11px;word-break:break-all">${f.md5}</div>
      <div style="font-size:11px;color:var(--text2);margin-top:8px;margin-bottom:3px">SHA256</div>
      <div class="mono" style="font-size:11px;word-break:break-all">${f.sha256}</div>
    </div>
    <a href="https://www.virustotal.com/gui/file/${f.sha256}" target="_blank" style="display:inline-block;margin-top:12px;font-size:12px;color:var(--accent)">🔗 Xem trên VirusTotal</a>`
    : `<div class="card-title">📄 Thông tin File</div><p style="color:var(--text2)">Không có thông tin file (phân tích URL).</p>`;

  // MITRE
  document.getElementById('card-mitre').innerHTML = `
    <div class="card-title">🎯 MITRE ATT&CK Techniques (${t.mitre.length})</div>
    <div class="mitre-grid">${t.mitre.map(m=>`
      <div class="mitre-chip">
        <div class="mid">${m.id}</div>
        <div class="mname">${m.name}</div>
        <div class="mtac">${m.tactic}</div>
      </div>`).join('')}</div>`;

  // Network
  document.getElementById('card-network').innerHTML = `
    <div class="card-title">🌐 Hoạt động mạng</div>
    <div class="tabs" style="margin-bottom:14px">
      <div class="tab active" onclick="netTab('ips',this)">IPs (${net.ips.length})</div>
      <div class="tab" onclick="netTab('domains',this)">Domains (${net.domains.length})</div>
      <div class="tab" onclick="netTab('http',this)">HTTP (${net.http.length})</div>
    </div>
    <div id="net-ips" class="tag-list">${net.ips.map(ip=>`<span class="tag tag-ip" title="Click để copy" onclick="copyText('${ip}')">${ip}</span>`).join('')||'<span style="color:var(--text2);font-size:13px">Không có</span>'}</div>
    <div id="net-domains" style="display:none" class="tag-list">${net.domains.map(d=>`<span class="tag tag-domain" onclick="copyText('${d}')">${d}</span>`).join('')||'<span style="color:var(--text2);font-size:13px">Không có</span>'}</div>
    <div id="net-http" style="display:none">
      ${net.http.length ? `<div class="table-wrap"><table><thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>
      ${net.http.map(h=>`<tr><td><span style="color:var(--accent);font-weight:600">${h.method}</span></td><td class="mono" style="word-break:break-all;max-width:400px">${h.url}</td><td>${h.status}</td></tr>`).join('')}
      </tbody></table></div>` : '<span style="color:var(--text2);font-size:13px">Không có HTTP</span>'}
    </div>`;

  // Process
  const inj = pr.injected.length;
  document.getElementById('card-process').innerHTML = `
    <div class="card-title">⚙️ Hoạt động tiến trình</div>
    <div class="grid-3" style="margin-bottom:16px">
      <div class="stat-box"><div class="val" style="font-size:22px;color:var(--red)">${inj}</div><div class="lbl">Tiến trình bị inject</div></div>
      <div class="stat-box"><div class="val" style="font-size:22px;color:var(--orange)">${pr.dropped.length}</div><div class="lbl">Files dropped</div></div>
      <div class="stat-box"><div class="val" style="font-size:22px;color:var(--yellow)">${pr.registry.length}</div><div class="lbl">Registry keys</div></div>
    </div>
    ${pr.dropped.length ? `<div style="margin-top:8px"><div style="font-size:12px;color:var(--text2);margin-bottom:8px;font-weight:600">FILES DROPPED</div>
    ${pr.dropped.map(f=>`<div class="proc-item malicious">📄 ${f.name}</div>`).join('')}</div>` : ''}
    ${pr.registry.length ? `<div style="margin-top:12px"><div style="font-size:12px;color:var(--text2);margin-bottom:8px;font-weight:600">REGISTRY KEYS</div>
    ${pr.registry.slice(0,8).map(k=>`<div class="proc-item" style="font-size:11px">${k}</div>`).join('')}</div>` : ''}`;
}

function netTab(id, el) {
  ['ips','domains','http'].forEach(t => document.getElementById('net-'+t).style.display = 'none');
  document.getElementById('net-'+id).style.display = id==='http'?'block':'flex';
  document.getElementById('net-'+id).style.flexWrap = 'wrap';
  el.parentElement.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
}

function renderPlaybook(d) {
  const p = d.playbook;
  const phaseMap = {};
  p.actions.forEach(a => { (phaseMap[a.phase] = phaseMap[a.phase]||[]).push(a); });
  const pColors = { 1:'p1', 2:'p2', 3:'p3', 4:'p4' };
  const pIcons  = { 1:'🔴', 2:'🟠', 3:'🟡', 4:'🟢' };

  let html = `
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
        <span class="badge ${severityClass(p.threat_level)}">${p.severity}</span>
        <span style="font-size:18px;font-weight:700">${p.malware_name}</span>
      </div>
      <p style="color:var(--text2);font-size:13.5px;line-height:1.7;margin-bottom:10px">${p.summary}</p>
      <div style="background:var(--bg3);border-radius:8px;padding:14px;border-left:3px solid var(--accent);font-size:13px;line-height:1.7">${p.mitigation}</div>
    </div>`;

  Object.entries(phaseMap).forEach(([phase, acts]) => {
    html += `<div class="phase-group">
      <div class="phase-header" onclick="togglePhase(this)">
        📌 ${phase}
        <span class="count">${acts.length} hành động</span>
        <svg style="width:16px;height:16px;margin-left:8px;transition:transform 0.2s" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="phase-body open">`;
    acts.forEach(a => {
      html += `<div class="action-card ${pColors[a.priority]||''}">
        <div class="action-header">
          <span>${pIcons[a.priority]||''}</span>
          <span class="action-title">${a.title}</span>
          <span style="margin-left:auto;font-size:11px;color:var(--text2)">${a.category}</span>
        </div>
        <div class="action-desc">${a.description}</div>`;
      if (a.commands && a.commands.length) {
        html += `<div class="code-block">${a.commands.map(c =>
          c.startsWith('#')||!c.trim()
            ? `<span class="cmd-comment">${esc(c)}</span>`
            : `<span class="cmd-line">${esc(c)}</span>`
        ).join('\n')}</div>`;
      }
      if (a.notes && a.notes.length) {
        html += `<div class="action-notes">${a.notes.map(n=>`<div class="action-note">💡 <span>${esc(n)}</span></div>`).join('')}</div>`;
      }
      html += `</div>`;
    });
    html += `</div></div>`;
  });
  document.getElementById('playbook-content').innerHTML = html;
}

function togglePhase(el) {
  const body = el.nextElementSibling;
  const icon = el.querySelector('svg');
  body.classList.toggle('open');
  icon.style.transform = body.classList.contains('open') ? '' : 'rotate(-90deg)';
}

function renderIOCs(d) {
  const b = d.playbook.ioc_blocklist;
  document.getElementById('ioc-content').innerHTML = `
    <div class="grid-2">
      <div class="card">
        <div class="card-title">🔴 IP Addresses (${b.ip_addresses.length})</div>
        <div class="tag-list">${b.ip_addresses.map(v=>`<span class="tag tag-ip" onclick="copyText('${v}')" title="Click để copy">${v}</span>`).join('')||'<span style="color:var(--text2)">Không có</span>'}</div>
      </div>
      <div class="card">
        <div class="card-title">🟠 Domains (${b.domains.length})</div>
        <div class="tag-list">${b.domains.map(v=>`<span class="tag tag-domain" onclick="copyText('${v}')" title="Click để copy">${v}</span>`).join('')||'<span style="color:var(--text2)">Không có</span>'}</div>
      </div>
      <div class="card">
        <div class="card-title">🟢 URLs (${b.urls.length})</div>
        <div class="tag-list">${b.urls.map(v=>`<span class="tag tag-url" onclick="copyText('${v}')" title="Click để copy" style="word-break:break-all">${v}</span>`).join('')||'<span style="color:var(--text2)">Không có</span>'}</div>
      </div>
      <div class="card">
        <div class="card-title">🟣 File Hashes (${b.file_hashes.length})</div>
        <div class="tag-list">${b.file_hashes.map(v=>`<span class="tag tag-hash" onclick="copyText('${v}')" title="Click để copy" style="word-break:break-all;font-size:10px">${v}</span>`).join('')||'<span style="color:var(--text2)">Không có</span>'}</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">🟡 Filenames (${b.filenames.length})</div>
      <div class="tag-list">${b.filenames.map(v=>`<span class="tag tag-file" onclick="copyText('${v}')">${v}</span>`).join('')||'<span style="color:var(--text2)">Không có</span>'}</div>
    </div>
    <div class="card">
      <div class="card-title">📋 Firewall Block Rules (PowerShell)</div>
      <div class="code-block">${
        b.ip_addresses.map(ip=>`<span class="cmd-line">netsh advfirewall firewall add rule name="Block_${ip}" dir=out action=block remoteip=${ip}</span>`).join('\n')
        + (b.domains.length ? '\n\n<span class="cmd-comment"># Thêm vào C:\\Windows\\System32\\drivers\\etc\\hosts:</span>\n' +
          b.domains.map(d=>`<span class="cmd-line">0.0.0.0 ${d}</span>`).join('\n') : '')
      }</div>
    </div>`;
}

function renderHistory(tasks) {
  if (!tasks.length) {
    document.getElementById('history-content').innerHTML = '<div class="card"><p style="color:var(--text2)">Không có task nào.</p></div>';
    return;
  }
  const rows = tasks.map(t => {
    const verdict = (t.verdict?.threatLevelText || 'unknown').toLowerCase();
    const cls = verdict.includes('malicious') ? 'verdict-malicious' : verdict.includes('suspicious') ? 'verdict-suspicious' : 'verdict-clean';
    return `<tr>
      <td class="mono" style="font-size:11px">${t.uuid||''}</td>
      <td>${t.name||'N/A'}</td>
      <td class="${cls}">${t.verdict?.threatLevelText||'unknown'}</td>
      <td style="color:var(--text2)">${(t.date||'').slice(0,10)}</td>
      <td><button class="btn btn-outline" style="padding:4px 12px;font-size:12px" onclick="analyzeFromHistory('${t.uuid}')">Phân tích</button></td>
    </tr>`;
  }).join('');
  document.getElementById('history-content').innerHTML = `
    <div class="card"><div class="table-wrap">
    <table><thead><tr><th>UUID</th><th>Tên</th><th>Verdict</th><th>Ngày</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}

async function analyzeFromHistory(uuid) {
  document.getElementById('task-uuid').value = uuid;
  showPage('analyze', document.querySelector('[data-page=analyze]'));
  switchTab('tab-uuid');
  await analyzeTask();
}

// ── Export ────────────────────────────────────────────────────────────────────
async function exportReport(fmt) {
  if (!G.data) return toast('Chưa có dữ liệu để xuất', 'err');
  try {
    const r = await fetch('/api/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: fmt, data: G.data })
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    toast(`Đã xuất: ${j.path}`);
  } catch (e) { toast(e.message, 'err'); }
}

function copyAllIOCs() {
  if (!G.data) return toast('Chưa có IOC', 'err');
  const b = G.data.playbook.ioc_blocklist;
  const txt = [
    '# IPs', ...b.ip_addresses,
    '# Domains', ...b.domains,
    '# Hashes', ...b.file_hashes,
  ].join('\n');
  navigator.clipboard.writeText(txt).then(() => toast('Đã copy tất cả IOC!'));
}

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => toast('Đã copy: ' + txt));
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
