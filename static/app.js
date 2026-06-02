// ── State ────────────────────────────────────────────────────────────────────
let G = {
  data: null,
  apiKey: localStorage.getItem('ir_apikey') || '',
  aiController: null,
  aiRequestId: 0
};
const LAST_ANALYSIS_KEY = 'ir_last_analysis_payload';

window.onload = async () => {
  if (G.apiKey) document.getElementById('api-key-input').value = G.apiKey;
  document.getElementById('hist-key').value = G.apiKey;
  if (restoreLastAnalysis()) {
    await persistCurrentAnalysis('browser:restore');
  } else {
    await restoreLatestFromServer();
  }
  await loadHistory();
  await loadGhidraStatus();
  animateCards(document);
};

// ── Navigation ───────────────────────────────────────────────────────────────
function showPage(id, el) {
  const target = document.getElementById('page-' + id);
  document.querySelectorAll('[id^="page-"]').forEach(p => {
    p.style.display = p === target ? 'block' : 'none';
    p.classList.remove('page-enter');
  });
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.remove('active');
    n.removeAttribute('aria-current');
  });
  if (el) {
    el.classList.add('active');
    el.setAttribute('aria-current', 'page');
  }
  if (target) {
    void target.offsetWidth;
    target.classList.add('page-enter');
    animateCards(target);
  }
}

function switchTab(id) {
  const paneId = 'pane-' + id.replace('tab-', '');
  document.querySelectorAll('[role="tab"]').forEach(t => {
    const active = t.id === id;
    t.classList.toggle('active', active);
    t.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[role="tabpanel"]').forEach(p => {
    const active = p.id === paneId;
    p.classList.toggle('active', active);
    p.hidden = !active;
  });
}

function openImportJson() {
  showPage('analyze', document.querySelector('[data-page=analyze]'));
  switchTab('tab-import');
}

function showDashboard() {
  showPage('dashboard', document.querySelector('[data-page=dashboard]'));
}

function animateCards(scope = document) {
  const items = scope.querySelectorAll('.card, .ghidra-panel, .stat-box, .topic-stage, .home-card, .home-metric, .flow-step, .action-card, .mitre-chip');
  items.forEach((item, idx) => {
    item.classList.remove('stagger-item');
    item.style.setProperty('--delay', `${Math.min(idx * 45, 360)}ms`);
    void item.offsetWidth;
    item.classList.add('stagger-item');
  });
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
  const loading = document.getElementById('analyze-loading');
  loading.style.display = 'block';
  loading.setAttribute('aria-busy', 'true');
  document.getElementById('loading-msg').textContent = msg;
}
function hideLoading() {
  const loading = document.getElementById('analyze-loading');
  loading.style.display = 'none';
  loading.setAttribute('aria-busy', 'false');
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
    showDashboard();
    toast(`Demo ${malware.toUpperCase()} đã tải xong!`);
  } catch (e) { toast(e.message, 'err'); }
  finally { hideLoading(); }
}

async function analyzeTask() {
  const key = getKey();
  const taskInput = document.getElementById('task-uuid');
  const taskRef = taskInput.value.trim();
  const uuid = extractTaskUuid(taskRef);
  if (!key)  return toast('Nhập API key trước', 'err');
  if (!uuid) return toast('Nhập Task UUID', 'err');
  taskInput.value = uuid;
  showLoading('Đang lấy dữ liệu từ Any.Run...');
  try {
    const r = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key, task_id: uuid, task_ref: taskRef })
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAll(j.data);
    showDashboard();
    toast('Phân tích hoàn tất!');
  } catch (e) { toast(e.message, 'err'); }
  finally { hideLoading(); }
}

function extractTaskUuid(value) {
  const match = String(value || '').match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return match ? match[0] : '';
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
  setProgress(5);
  document.getElementById('progress-pct').textContent = '5%';
  document.getElementById('progress-msg').textContent = 'Đã submit lên Any.Run sandbox...';
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {
    try {
      const r = await fetch(`/api/task_status/${task_id}`);
      const j = await r.json();
      if (!j.ok) { clearInterval(_pollTimer); return; }
      setProgress(j.progress);
      document.getElementById('progress-pct').textContent = j.progress + '%';
      document.getElementById('progress-msg').textContent = j.message;
      if (j.status === 'done') {
        clearInterval(_pollTimer);
        document.getElementById('progress-panel').style.display = 'none';
        renderAll(j.data);
        showDashboard();
        toast('Phân tích hoàn tất!');
      } else if (j.status === 'error') {
        clearInterval(_pollTimer);
        document.getElementById('progress-panel').style.display = 'none';
        toast('Lỗi: ' + j.message, 'err');
      }
    } catch(e) { /* mạng tạm lỗi, thử lại */ }
  }, 5000);
}

function setProgress(progress) {
  const pct = Math.max(0, Math.min(100, Number(progress) || 0));
  const bar = document.getElementById('progress-bar');
  const track = bar?.parentElement;
  if (bar) bar.style.transform = `scaleX(${pct / 100})`;
  if (track) track.setAttribute('aria-valuenow', String(Math.round(pct)));
}

// Mở thư mục reports
async function openReports() {
  await fetch('/api/open_reports');
  toast('Đã mở thư mục reports!');
}

let selectedFile = null;
let selectedReportJson = null;
let selectedIocJson = null;
let selectedGhidraFile = null;

function handleJsonSelect(inp, kind) {
  const file = inp.files[0] || null;
  if (kind === 'report') selectedReportJson = file;
  if (kind === 'ioc') selectedIocJson = file;
  const reportName = selectedReportJson ? selectedReportJson.name : 'chưa chọn Results .md / JSON report';
  const iocName = selectedIocJson ? selectedIocJson.name : 'không có IOC JSON riêng';
  document.getElementById('json-import-result').textContent = `Report: ${reportName} | IOC: ${iocName}`;
}

async function analyzeJsonImport() {
  if (!selectedReportJson) return toast('Chọn file Any.Run Results .md hoặc JSON report trước', 'err');
  const fd = new FormData();
  fd.append('report_file', selectedReportJson);
  if (selectedIocJson) fd.append('ioc_file', selectedIocJson);
  const supplemental = document.getElementById('supplemental-text')?.value.trim();
  if (supplemental) fd.append('supplemental_text', supplemental);
  showLoading('Đang import report và tạo IR playbook...');
  try {
    const r = await fetch('/api/analyze/json', { method:'POST', body:fd });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAll(j.data);
    showDashboard();
    toast('Import report hoàn tất!');
  } catch(e) { toast(e.message, 'err'); }
  finally { hideLoading(); }
}

function handleFileSelect(inp) {
  selectedFile = inp.files[0];
  if (selectedFile) document.getElementById('file-name').textContent = '📄 ' + selectedFile.name;
}

function handleUploadZoneKey(e) {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  e.preventDefault();
  document.getElementById('file-input').click();
}
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('dragover');
  selectedFile = e.dataTransfer.files[0];
  if (selectedFile) document.getElementById('file-name').textContent = '📄 ' + selectedFile.name;
}

function handleGhidraSelect(inp) {
  selectedGhidraFile = inp.files[0] || null;
  updateGhidraFilePreview();
}

function handleGhidraZoneKey(e) {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  e.preventDefault();
  document.getElementById('ghidra-file-input').click();
}

function handleGhidraDrop(e) {
  e.preventDefault();
  document.getElementById('ghidra-drop-zone').classList.remove('dragover');
  selectedGhidraFile = e.dataTransfer.files[0] || null;
  const input = document.getElementById('ghidra-file-input');
  try {
    if (input && e.dataTransfer.files.length) input.files = e.dataTransfer.files;
  } catch (_err) {
    // Some browsers keep input.files read-only; selectedGhidraFile is enough for submit.
  }
  updateGhidraFilePreview();
}

function updateGhidraFilePreview() {
  const nameEl = document.getElementById('ghidra-file-name');
  const result = document.getElementById('ghidra-result');
  const zone = document.getElementById('ghidra-drop-zone');
  if (!selectedGhidraFile) {
    if (nameEl) nameEl.textContent = 'Kéo thả mẫu local hoặc nhấn để chọn';
    zone?.classList.remove('has-file');
    return;
  }
  if (nameEl) nameEl.textContent = selectedGhidraFile.name;
  zone?.classList.add('has-file');
  if (result) {
    result.innerHTML = `
      <div class="ghidra-selection inline-note">
        <b>${esc(selectedGhidraFile.name)}</b>
        <span>${formatFileSize(selectedGhidraFile.size)} • sẵn sàng phân tích local</span>
      </div>`;
  }
}

function setGhidraTimeout(seconds) {
  const input = document.getElementById('ghidra-timeout');
  if (input) input.value = seconds;
  document.querySelectorAll('.timeout-presets .chip-btn').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.includes(String(seconds)));
  });
}

async function loadGhidraStatus() {
  const statusEl = document.getElementById('ghidra-status');
  if (!statusEl) return;
  statusEl.className = 'ghidra-status checking';
  statusEl.innerHTML = '<span class="status-dot"></span><b>Đang kiểm tra Ghidra</b><small>Đọc cấu hình GHIDRA_HOME/GHIDRA_HEADLESS/PATH...</small>';
  try {
    const r = await fetch('/api/ghidra/status');
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'Không kiểm tra được Ghidra');
    const s = j.data;
    statusEl.className = 'ghidra-status ' + (s.available ? 'ok' : 'warn');
    statusEl.innerHTML = s.available
      ? `<span class="status-dot"></span><b>Ghidra đã sẵn sàng</b><code>${esc(s.analyze_headless)}</code>`
      : `<span class="status-dot"></span><b>Chưa cấu hình Ghidra</b><small>${esc(s.setup_hint)}</small>`;
  } catch (e) {
    statusEl.className = 'ghidra-status warn';
    statusEl.innerHTML = `<span class="status-dot"></span><b>Lỗi kiểm tra</b><small>${esc(e.message)}</small>`;
  }
}

async function analyzeGhidraFile() {
  if (!selectedGhidraFile) return toast('Chọn file mẫu để phân tích Ghidra trước', 'err');
  const fd = new FormData();
  fd.append('sample_file', selectedGhidraFile);
  fd.append('timeout', document.getElementById('ghidra-timeout')?.value || '180');
  document.getElementById('ghidra-result').innerHTML = `
    <div class="ghidra-loading loading-wrap compact">
      <div class="spinner"></div>
      <p>Đang phân tích tĩnh local...</p>
      <div class="ghidra-loading-steps">
        <span>Hash</span><span>Entropy</span><span>Strings</span><span>Ghidra headless</span>
      </div>
    </div>`;
  try {
    const r = await fetch('/api/ghidra/analyze', { method: 'POST', body: fd });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderGhidraResult(j.data);
    toast('Phân tích tĩnh hoàn tất!');
  } catch (e) {
    document.getElementById('ghidra-result').innerHTML = `<div class="inline-note danger">${esc(e.message)}</div>`;
    toast(e.message, 'err');
  }
}

function renderGhidraResult(data) {
  const triage = data.triage || {};
  const ghidra = data.ghidra || {};
  const summary = ghidra.summary || {};
  const enrich = data.ir_enrichment || {};
  const entropy = Number(triage.entropy || 0);
  const iocTotal = ['urls', 'domains', 'ips', 'registry'].reduce((n, key) => n + ((triage[key] || []).length), 0);
  const suspiciousApis = [...(triage.suspicious_apis || []), ...(summary.suspicious_imports || [])];
  const uniqueApis = [...new Set(suspiciousApis)];
  const isGhidraOk = ghidra.status === 'ok';
  const riskLabel = entropy >= 7.2 ? 'Cao' : entropy >= 6.4 ? 'Trung bình' : 'Thấp';
  const riskClass = entropy >= 7.2 ? 'critical' : entropy >= 6.4 ? 'medium' : 'clean';
  const list = (items = [], cls = '') => {
    if (!items.length) return '<span class="empty-inline">Không có</span>';
    const visible = items.slice(0, 14).map(x => {
      const encoded = encodeURIComponent(String(x));
      return `<span class="tag ${cls}" onclick="copyText(decodeURIComponent('${encoded}'))">${esc(x)}</span>`;
    }).join('');
    const more = items.length > 14 ? `<span class="tag tag-more">+${items.length - 14}</span>` : '';
    return visible + more;
  };
  const kv = (label, value, mono = false) => `
    <div class="static-kv">
      <span>${label}</span>
      ${mono ? `<code>${esc(value || 'N/A')}</code>` : `<b>${esc(value || 'N/A')}</b>`}
    </div>`;
  const miniList = (items = [], limit = 8) => {
    if (!items.length) return '<li>Chưa có dữ liệu.</li>';
    return items.slice(0, limit).map(x => `<li>${esc(x)}</li>`).join('');
  };
  const ghidraState = isGhidraOk
    ? `<span class="badge clean">Ghidra OK</span>`
    : `<span class="badge medium">${esc(ghidra.status || 'not_configured')}</span>`;
  document.getElementById('ghidra-result').innerHTML = `
    <div class="ghidra-summary-grid">
      <div class="stat-box">
        <div class="val">${esc(entropy ? entropy.toFixed(2) : 'N/A')}</div>
        <div class="lbl">Entropy</div>
        <span class="badge ${riskClass}">${riskLabel}</span>
      </div>
      <div class="stat-box">
        <div class="val">${iocTotal}</div>
        <div class="lbl">IOC tĩnh</div>
      </div>
      <div class="stat-box">
        <div class="val">${uniqueApis.length}</div>
        <div class="lbl">API đáng ngờ</div>
      </div>
      <div class="stat-box">
        <div class="val">${esc(summary.function_count ?? 'N/A')}</div>
        <div class="lbl">Functions</div>
        ${ghidra.duration_seconds ? `<span class="mini-metric">${esc(ghidra.duration_seconds)}s</span>` : ''}
      </div>
    </div>

    <div class="ghidra-detail-grid">
      <div class="ghidra-panel">
        <div class="card-title">Static triage</div>
        ${kv('File', triage.filename)}
        ${kv('Size', formatFileSize(triage.size))}
        ${kv('Type', triage.file_type)}
        ${kv('MD5', triage.md5, true)}
        ${kv('SHA1', triage.sha1, true)}
        ${kv('SHA256', triage.sha256, true)}
      </div>

      <div class="ghidra-panel">
        <div class="card-title">Ghidra headless</div>
        <div class="ghidra-state-row">${ghidraState}</div>
        ${kv('Format', summary.executable_format)}
        ${kv('Language', summary.language)}
        ${kv('Compiler', summary.compiler)}
        ${kv('Image base', summary.image_base, true)}
        ${kv('Entry point', summary.entry_point, true)}
        ${ghidra.error ? `<div class="inline-note danger">${esc(ghidra.error)}</div>` : ''}
      </div>
    </div>

    <div class="ghidra-panel">
      <div class="card-title">IOC tĩnh để đối chiếu Any.Run</div>
      <div class="ioc-grid">
        <div class="static-section"><b>URLs</b><div class="tag-list">${list(triage.urls, 'tag-url')}</div></div>
        <div class="static-section"><b>Domains</b><div class="tag-list">${list(triage.domains, 'tag-domain')}</div></div>
        <div class="static-section"><b>IPs</b><div class="tag-list">${list(triage.ips, 'tag-ip')}</div></div>
        <div class="static-section"><b>Registry</b><div class="tag-list">${list(triage.registry, 'tag-file')}</div></div>
      </div>
    </div>

    <div class="ghidra-detail-grid">
      <div class="ghidra-panel">
        <div class="card-title">Reverse engineering leads</div>
        <div class="static-section"><b>Suspicious APIs</b><div class="tag-list">${list(uniqueApis, 'tag-hash')}</div></div>
        <div class="static-section"><b>Imports</b><ul class="compact-list">${miniList(summary.imports, 10)}</ul></div>
        <div class="static-section"><b>Functions</b><ul class="compact-list">${miniList(summary.functions, 10)}</ul></div>
      </div>

      <div class="ghidra-panel">
        <div class="card-title">IR next steps</div>
        <ul class="ai-list">${(enrich.recommended_ir_actions || []).map(x => `<li>${esc(x)}</li>`).join('') || '<li>Đối chiếu hash, IOC và API với telemetry Any.Run/SIEM.</li>'}</ul>
        <div class="inline-note">${esc(enrich.evidence_note || 'Static analysis là bằng chứng bổ sung cho điều tra runtime.')}</div>
      </div>
    </div>`;
  animateCards(document.getElementById('ghidra-result'));
}


async function loadHistory() {
  const key = document.getElementById('hist-key').value.trim() || getKey();
  document.getElementById('history-content').innerHTML = '<div class="loading-wrap"><div class="spinner"></div><p>Đang tải lịch sử...</p></div>';
  try {
    const localRes = await fetch('/api/history/local');
    const localJson = await localRes.json();
    if (!localJson.ok) throw new Error(localJson.error);

    let anyrunTasks = [];
    let anyrunError = '';
    if (key) {
      try {
        const r = await fetch('/api/history', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: key })
        });
        const j = await r.json();
        if (!j.ok) throw new Error(j.error);
        anyrunTasks = j.tasks || [];
      } catch (e) {
        anyrunError = e.message;
      }
    }
    renderCombinedHistory(localJson.items || [], anyrunTasks, anyrunError);
  } catch (e) {
    document.getElementById('history-content').innerHTML = `<div class="card"><span style="color:var(--red)">${e.message}</span></div>`;
    toast(e.message, 'err');
  }
}

// ── Render functions ──────────────────────────────────────────────────────────
function renderAll(data, options = {}) {
  G.data = data;
  saveLastAnalysis(data);
  renderDashboard(data);
  renderPlaybook(data);
  renderIOCs(data);
  renderAIProactive(data);
  if (!options.silent && data.cache?.hit) toast('Dùng lại lịch sử: ' + data.cache.reason);
}

function saveLastAnalysis(data) {
  try {
    localStorage.setItem(LAST_ANALYSIS_KEY, JSON.stringify(data));
  } catch (e) {
    console.warn('Không thể lưu phiên phân tích gần nhất:', e);
  }
}

async function persistCurrentAnalysis(source = 'browser') {
  if (!G.data) return false;
  try {
    const r = await fetch('/api/history/local/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: G.data, source })
    });
    const j = await r.json();
    return !!j.ok;
  } catch (e) {
    console.warn('Không thể đồng bộ lịch sử local:', e);
    return false;
  }
}

function restoreLastAnalysis() {
  try {
    const raw = localStorage.getItem(LAST_ANALYSIS_KEY);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !data.playbook || !data.threat) return false;
    G.data = data;
    renderDashboard(data);
    renderPlaybook(data);
    renderIOCs(data);
    renderAIProactive(data);
    return true;
  } catch (e) {
    localStorage.removeItem(LAST_ANALYSIS_KEY);
    return false;
  }
}

async function restoreLatestFromServer() {
  try {
    const r = await fetch('/api/history/local/latest');
    const j = await r.json();
    if (!j.ok || !j.data) return;
    renderAll(j.data, { silent: true });
  } catch (e) {
    // Không có lịch sử thì giữ màn hình chờ bình thường.
  }
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

function clampScore(value, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function buildThreatGauge(score, lvl) {
  const pct = clampScore(score, Math.round((lvl / 4) * 100));
  return `
    <div class="threat-gauge" style="--gauge-pct:${pct};--gauge-color:${severityColor(lvl)}">
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <circle class="gauge-track" cx="60" cy="60" r="50" pathLength="100"></circle>
        <circle class="gauge-value" cx="60" cy="60" r="50" pathLength="100"></circle>
      </svg>
      <div class="gauge-center"><b>${pct}</b><span>/100</span></div>
    </div>`;
}

function isValidFileHash(value) {
  return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(String(value || '').trim());
}

function pickVirusTotalHash(fileInfo = {}) {
  return [fileInfo.sha256, fileInfo.sha1, fileInfo.md5].find(isValidFileHash) || '';
}

function renderHashValue(value) {
  return value ? esc(value) : '<span style="color:var(--text2)">N/A</span>';
}

function renderVirusTotalLink(fileInfo = {}) {
  const hash = pickVirusTotalHash(fileInfo);
  if (!hash) {
    return `<div style="margin-top:12px;font-size:12px;color:var(--yellow)">
      Không có hash hợp lệ để tra VirusTotal. Mục này có thể là URL analysis, import thiếu main-object hash, hoặc bản ghi lịch sử chỉ có metadata.
    </div>`;
  }
  return `<a href="https://www.virustotal.com/gui/file/${hash}" target="_blank" rel="noopener" title="Nếu VirusTotal trống: hash chưa từng được submit/public hoặc đây là hash demo/synthetic." style="display:inline-block;margin-top:12px;font-size:12px;color:var(--accent)">🔗 Xem trên VirusTotal</a>
    <div style="margin-top:6px;font-size:11px;color:var(--text2)">Tra cứu theo hash: <code>${esc(hash)}</code></div>`;
}

function formatFileSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size <= 0) return 'N/A';
  return `${(size / 1024).toFixed(1)} KB`;
}

function renderDashboard(d) {
  document.getElementById('dashboard-empty').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  const t = d.threat, p = d.playbook, net = d.network, pr = d.processes;
  const lvl = t.threat_level;
  const riskScore = p?.severity_score?.score;

  // Stats
  document.getElementById('stat-row').innerHTML = `
    <div class="stat-box stat-gauge">${buildThreatGauge(riskScore, lvl)}<div class="lbl">Threat Score</div></div>
    <div class="stat-box"><div class="val" style="color:var(--accent)">${t.mitre.length}</div><div class="lbl">MITRE Techniques</div></div>
    <div class="stat-box"><div class="val" style="color:var(--red)">${net.ips.length + net.domains.length}</div><div class="lbl">C2 Indicators</div></div>
  `;

  // Threat card
  document.getElementById('card-threat').classList.add('card-glow');
  const bar_w = Math.round((lvl / 4) * 100);
  let ml_html = '';
  if (t.ml && t.ml.status === 'success') {
      const mlColor = t.ml.prediction === 'Malicious' ? 'var(--red)' : t.ml.prediction === 'Suspicious' ? 'var(--orange)' : 'var(--green)';
      ml_html = `<div style="margin-top:14px;padding:10px;border-radius:6px;background:var(--bg3);border:1px solid var(--border)">
        <div style="font-size:11px;color:var(--text2);margin-bottom:4px;font-weight:600">🤖 MACHINE LEARNING ASSESSMENT</div>
        <div class="ml-row">
           <span style="font-size:14px;font-weight:600;color:${mlColor}">${t.ml.prediction}</span>
           <span style="font-size:13px;color:var(--text2)">Độ tin cậy: <b style="color:var(--text)">${t.ml.confidence}%</b></span>
        </div>
      </div>`;
  }
  const cache_html = d.cache?.hit ? `<div style="margin-top:12px;padding:10px;border-radius:6px;background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);font-size:12px;color:var(--green)">
    Dùng lại kết quả đã phân tích: ${esc(d.cache.reason || '')}
  </div>` : '';

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
    ${ml_html}
    ${cache_html}
    <div style="margin-top:14px;font-size:13px;color:var(--text2)">
      🖥️ ${d.os_env} &nbsp;|&nbsp; ⏱️ ${d.duration}s &nbsp;|&nbsp;
      <a href="${d.analysis_url}" target="_blank" style="color:var(--accent)">Xem trên Any.Run ↗</a>
    </div>`;

  // File card
  const f = d.file;
  document.getElementById('card-file').innerHTML = f ? `
    <div class="card-title">📄 Thông tin File</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:12px;word-break:break-all">${esc(f.name || 'N/A')}</div>
    <div style="font-size:13px;color:var(--text2);margin-bottom:8px">${esc(f.type || 'N/A')} &nbsp;|&nbsp; ${formatFileSize(f.size)}</div>
    <div style="margin-top:12px">
      <div style="font-size:11px;color:var(--text2);margin-bottom:3px">MD5</div>
      <div class="mono" style="font-size:11px;word-break:break-all">${renderHashValue(f.md5)}</div>
      <div style="font-size:11px;color:var(--text2);margin-top:8px;margin-bottom:3px">SHA1</div>
      <div class="mono" style="font-size:11px;word-break:break-all">${renderHashValue(f.sha1)}</div>
      <div style="font-size:11px;color:var(--text2);margin-top:8px;margin-bottom:3px">SHA256</div>
      <div class="mono" style="font-size:11px;word-break:break-all">${renderHashValue(f.sha256)}</div>
    </div>
    ${renderVirusTotalLink(f)}`
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
    <div class="tabs" role="tablist" aria-label="Loại chỉ báo mạng" style="margin-bottom:14px">
      <button type="button" class="tab active" role="tab" aria-selected="true" aria-controls="net-ips" onclick="netTab('ips',this)">IPs (${net.ips.length})</button>
      <button type="button" class="tab" role="tab" aria-selected="false" aria-controls="net-domains" onclick="netTab('domains',this)">Domains (${net.domains.length})</button>
      <button type="button" class="tab" role="tab" aria-selected="false" aria-controls="net-http" onclick="netTab('http',this)">HTTP (${net.http.length})</button>
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
  animateCards(document.getElementById('dashboard'));
}

function netTab(id, el) {
  ['ips','domains','http'].forEach(t => document.getElementById('net-'+t).style.display = 'none');
  document.getElementById('net-'+id).style.display = id==='http'?'block':'flex';
  document.getElementById('net-'+id).style.flexWrap = 'wrap';
  el.parentElement.querySelectorAll('.tab').forEach(t => {
    const active = t === el;
    t.classList.toggle('active', active);
    t.setAttribute('aria-selected', String(active));
  });
}

function renderPlaybook(d) {
  const p = d.playbook;
  const phaseMap = {};
  p.actions.forEach(a => { (phaseMap[a.phase] = phaseMap[a.phase]||[]).push(a); });
  const pColors = { 1:'p1', 2:'p2', 3:'p3', 4:'p4' };
  const pIcons  = { 1:'🔴', 2:'🟠', 3:'🟡', 4:'🟢' };
  const score = p.severity_score || {};
  const evalData = d.ir_evaluation || {};
  const timeline = p.timeline || [];
  const hunts = p.scope_hunting || [];

  let html = `
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
        <span class="badge ${severityClass(p.threat_level)}">${p.severity}</span>
        <span style="font-size:18px;font-weight:700">${p.malware_name}</span>
      </div>
      <p style="color:var(--text2);font-size:13.5px;line-height:1.7;margin-bottom:10px">${p.summary}</p>
      <div style="background:var(--bg3);border-radius:8px;padding:14px;border-left:3px solid var(--accent);font-size:13px;line-height:1.7">${p.mitigation}</div>
    </div>`;

  html += `
    <div class="card" style="margin-bottom:20px">
      <div class="card-title">Ma trận đánh giá mức độ</div>
      <div class="grid-3">
        <div class="stat-box stat-gauge">${buildThreatGauge(score.score, p.threat_level)}<div class="lbl">Risk Score</div></div>
        <div class="stat-box"><div class="val">${esc(score.recommended_severity || 'N/A')}</div><div class="lbl">Đề xuất</div></div>
        <div class="stat-box"><div class="val">${esc(evalData.readiness_score ?? 'N/A')}%</div><div class="lbl">IR Readiness</div></div>
      </div>
      <div style="margin-top:12px;color:var(--text2);font-size:13px;line-height:1.7">
        ${(score.reasons || []).map(r => `<div>• ${esc(r)}</div>`).join('') || 'Chưa có lý do scoring.'}
      </div>
      <div style="margin-top:12px;color:var(--text2);font-size:13px;line-height:1.7">
        Outputs: ${(evalData.detection_outputs || []).map(x => esc(x)).join(', ') || 'N/A'}
      </div>
    </div>`;

  if (timeline.length) {
    html += `<div class="card" style="margin-bottom:20px">
      <div class="card-title">Timeline điều tra</div>
      <div class="table-wrap"><table><thead><tr><th>Bước</th><th>Giai đoạn</th><th>Sự kiện</th><th>Bằng chứng</th><th>Hành động IR</th></tr></thead><tbody>
      ${timeline.map(row => `<tr>
        <td>${esc(row.step)}</td>
        <td>${esc(row.stage)}</td>
        <td>${esc(row.event)}</td>
        <td><code>${esc(row.evidence || 'N/A')}</code></td>
        <td>${esc(row.ir_action || '')}</td>
      </tr>`).join('')}
      </tbody></table></div>
    </div>`;
  }

  if (hunts.length) {
    html += `<div class="card" style="margin-bottom:20px">
      <div class="card-title">Scope & Threat Hunting</div>
      ${hunts.map(h => `<div class="action-card p2">
        <div class="action-header">
          <span>${esc(h.priority || 'P2')}</span>
          <span class="action-title">${esc(h.question || 'Hunting query')}</span>
          <span style="margin-left:auto;font-size:11px;color:var(--text2)">${esc(h.data_source || '')}</span>
        </div>
        <div class="action-desc">${esc(h.evidence || '')}</div>
        <div class="code-block"><span class="cmd-line">${esc(h.query || '')}</span></div>
      </div>`).join('')}
    </div>`;
  }

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
      html += `<div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0;font-size:11px;color:var(--text2)">
        <span class="tag">Owner: ${esc(a.owner || 'N/A')}</span>
        <span class="tag">SLA: ${esc(a.sla || 'N/A')}</span>
        <span class="tag">Status: ${esc(a.status || 'pending')}</span>
      </div>`;
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
      if (a.evidence_required && a.evidence_required.length) {
        html += `<div class="action-notes">${a.evidence_required.map(n=>`<div class="action-note">Evidence: <span>${esc(n)}</span></div>`).join('')}</div>`;
      }
      html += `</div>`;
    });
    html += `</div></div>`;
  });
  document.getElementById('playbook-content').innerHTML = html;
  animateCards(document.getElementById('playbook-content'));
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
  animateCards(document.getElementById('ioc-content'));
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

function renderCombinedHistory(localItems, anyrunTasks, anyrunError = '') {
  let html = renderLocalHistory(localItems);
  const hasKey = !!(document.getElementById('hist-key')?.value.trim() || getKey());
  if (hasKey || anyrunTasks.length || anyrunError) {
    html += `<div class="card"><div class="card-title">Any.Run task history</div>`;
    if (anyrunError) {
      const forbidden = /403|quyền truy cập|permission|forbidden/i.test(anyrunError);
      html += forbidden
        ? `<div class="history-api-status">
            <b>API key đang hoạt động nhưng không có quyền đọc lịch sử Any.Run.</b>
            <span>Endpoint <code>GET /analysis</code> trả 403. Một số gói/API key chỉ cho lấy report theo Task UUID hoặc submit phân tích, nhưng không cho liệt kê toàn bộ history.</span>
            <button type="button" class="btn btn-outline" onclick="showPage('analyze',document.querySelector('[data-page=analyze]'));switchTab('tab-uuid')">Nhập Task UUID để phân tích</button>
          </div>`
        : `<div class="history-api-status"><b>Không tải được Any.Run history.</b><span>${esc(anyrunError)}</span></div>`;
    } else if (!anyrunTasks.length) {
      html += `<p style="color:var(--text2);font-size:13px;margin-bottom:10px">API key hợp lệ nhưng Any.Run không trả task nào trong history hiện tại.</p>`;
    }
    if (anyrunTasks.length) {
      html += renderAnyRunHistoryTable(anyrunTasks);
    }
    html += `</div>`;
  }
  document.getElementById('history-content').innerHTML = html;
}

function renderAnyRunHistoryTable(tasks) {
  const rows = tasks.map(t => {
    const verdictText = t.verdict?.threatLevelText || t.threatLevelText || t.verdict || 'unknown';
    const verdict = String(verdictText).toLowerCase();
    const cls = verdict.includes('malicious') ? 'verdict-malicious' : verdict.includes('suspicious') ? 'verdict-suspicious' : 'verdict-clean';
    const uuid = extractAnyRunTaskUuid(t);
    const name = t.name || t.filename || t.fileName || t.obj_name || 'N/A';
    const date = t.date || t.created || t.created_at || t.createTime || '';
    return `<tr>
      <td class="mono" style="font-size:11px">${esc(uuid)}</td>
      <td>${esc(name)}</td>
      <td class="${cls}">${esc(verdictText)}</td>
      <td style="color:var(--text2)">${esc(String(date).slice(0,10))}</td>
      <td>${uuid ? `<button class="btn btn-outline" style="padding:4px 12px;font-size:12px" onclick="analyzeFromHistory('${escAttr(uuid)}')">Phân tích</button>` : ''}</td>
    </tr>`;
  }).join('');
  return `<div class="table-wrap"><table><thead><tr><th>UUID</th><th>Tên</th><th>Verdict</th><th>Ngày</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function extractAnyRunTaskUuid(task = {}) {
  const direct = task.uuid || task.task_uuid || task.taskUuid || task.id || task.analysis_id || '';
  if (direct) return String(direct);
  const haystack = [task.related, task.json, task.misp, task.html, task.url, task.analysis_url].filter(Boolean).join(' ');
  const match = haystack.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return match ? match[0] : '';
}

function renderLocalHistory(items) {
  if (!items.length) {
    return '<div class="card"><div class="card-title">Lịch sử cục bộ</div><p style="color:var(--text2)">Chưa có lần phân tích nào được lưu trong app.</p></div>';
  }
  const rows = items.map(t => {
    const cls = (t.threat_level || 0) >= 2 ? 'verdict-malicious' : (t.threat_level || 0) === 1 ? 'verdict-suspicious' : 'verdict-clean';
    return `<tr>
      <td>${esc(t.malware_name || 'Unknown')}</td>
      <td>${esc(t.file_name || 'N/A')}</td>
      <td class="${cls}">${esc(t.verdict || 'unknown')}</td>
      <td style="color:var(--text2)">${esc((t.created_at || '').replace('T', ' '))}</td>
      <td><button class="btn btn-outline" style="padding:4px 12px;font-size:12px" onclick="analyzeLocalHistory('${encodeURIComponent(t.id)}')">Mở lại</button></td>
    </tr>`;
  }).join('');
  return `<div class="card">
    <div class="card-title">Lịch sử cục bộ (${items.length})</div>
    <div style="font-size:12px;color:var(--text2);margin-bottom:12px">Các malware family đã có ở đây sẽ được ưu tiên dùng lại thay vì tạo playbook mới.</div>
    <div class="table-wrap"><table><thead><tr><th>Malware</th><th>File</th><th>Verdict</th><th>Thời gian</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
  </div>`;
}

async function analyzeLocalHistory(encodedId) {
  try {
    const r = await fetch('/api/history/local/' + encodedId);
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAll(j.data);
    showDashboard();
    toast('Đã mở lại kết quả trong lịch sử');
  } catch(e) { toast(e.message, 'err'); }
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
  const target = window.event?.currentTarget;
  navigator.clipboard.writeText(txt).then(() => {
    if (target?.classList) {
      target.classList.remove('copied');
      void target.offsetWidth;
      target.classList.add('copied');
      setTimeout(() => target.classList.remove('copied'), 900);
    }
    toast('Đã copy: ' + txt);
  });
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function escAttr(s) {
  return esc(s).replace(/'/g, '&#39;').replace(/"/g, '&quot;');
}

function renderAIProactive(d) {
  const answerEl = document.getElementById('ai-answer');
  if (!answerEl) return;
  const p = d.playbook || {};
  const t = d.threat || {};
  const net = d.network || { ips: [], domains: [] };
  const pr = d.processes || { dropped: [], registry: [], injected: [] };
  const ma = d.malware_analysis || {};
  const p0 = (p.actions || []).filter(a => a.priority === 1).slice(0, 3);
  const nextQuestions = [
    'Host nào khác từng kết nối tới IOC này?',
    'File đầu vào đến từ email, web hay share nội bộ?',
    'Tài khoản nào đăng nhập trước thời điểm malware chạy?'
  ];
  answerEl.innerHTML = `
    <div class="ai-mode">AI briefing chủ động</div>
    <div class="ai-brief-grid">
      <div class="ai-brief-item"><span>Mức khẩn cấp</span><b>${esc(p.severity || 'UNKNOWN')}</b></div>
      <div class="ai-brief-item"><span>Malware</span><b>${esc(p.malware_name || t.threat_name || 'Unknown')}</b></div>
      <div class="ai-brief-item"><span>C2</span><b>${(net.ips || []).length + (net.domains || []).length} IOC</b></div>
      <div class="ai-brief-item"><span>Artifact</span><b>${(pr.dropped || []).length} file / ${(pr.registry || []).length} registry</b></div>
    </div>
    <div class="ai-section-title">Nhận định ban đầu</div>
    <ul class="ai-list">${(ma.behavior || []).slice(0, 3).map(v => `<li>${esc(v)}</li>`).join('') || '<li>Chưa đủ dữ liệu để dựng chuỗi hành vi, cần bổ sung log endpoint/DNS/proxy.</li>'}</ul>
    <div class="ai-section-title">Việc nên làm ngay</div>
    <ol class="ai-list">${p0.map(a => `<li><b>${esc(a.title || 'Hành động')}</b>: ${esc(a.description || '')}</li>`).join('') || '<li>Cô lập endpoint, thu thập bằng chứng và chặn IOC trước khi phục hồi.</li>'}</ol>
    <div class="ai-section-title">AI muốn xác minh tiếp</div>
    <ul class="ai-list">${nextQuestions.map(q => `<li>${q}</li>`).join('')}</ul>
    <div class="ai-suggestion-row">
      <button class="btn btn-outline" onclick="askAI('Hãy chủ động đánh giá sự cố này như trưởng ca SOC')">Tạo briefing đầy đủ</button>
      <button class="btn btn-outline" onclick="askAI('Phân tích nguồn lây, cách lan truyền và phạm vi cần hunt')">Hunt phạm vi</button>
    </div>`;
}

async function askAILegacy(question = '') {
  return askAI(question);
}

function setAIControlsRunning(isRunning) {
  const stopBtn = document.getElementById('ai-stop-btn');
  if (stopBtn) stopBtn.disabled = !isRunning;
}

function stopAI(showToast = true) {
  if (!G.aiController) return;
  G.aiController.abort();
  G.aiController = null;
  setAIControlsRunning(false);
  if (showToast) toast('Đã dừng AI');
}

async function askAI(question = '') {
  if (!G.data) return toast('Chưa có dữ liệu phân tích để hỏi AI', 'err');
  stopAI(false);
  const requestId = ++G.aiRequestId;
  const controller = new AbortController();
  G.aiController = controller;
  setAIControlsRunning(true);

  const input = document.getElementById('ai-question');
  const q = (question || input.value || '').trim();
  const answerEl = document.getElementById('ai-answer');
  let streamedAnswer = '';
  let meta = { mode: 'local_fallback', model: '' };
  answerEl.innerHTML = '<div class="ai-bubble"><span class="typing-dots"><span></span><span></span><span></span></span>AI đang phân tích dữ liệu sự cố...</div>';

  const modeLabel = {
    openai: 'OpenAI',
    ollama: 'Ollama local LLM',
    local: 'Local assistant',
    fast_local: 'Fast local assistant',
    ollama_fallback: 'Local assistant (Ollama timeout)',
    guardrail: 'Scope guardrail',
    local_fallback: 'Local assistant'
  };

  const renderAnswer = (meta, answer, latencyMs) => {
    if (G.aiRequestId !== requestId) return;
    const label = modeLabel[meta.mode] || 'Local assistant';
    const warningHtml = meta.warning ? `<div class="ai-warning">${esc(meta.warning)}</div>` : '';
    const parts = [meta.model, latencyMs !== undefined ? `${latencyMs}ms` : 'streaming...'].filter(Boolean);
    answerEl.innerHTML = `<div class="ai-mode">${label}${parts.length ? ` · ${esc(parts.join(' · '))}` : ''}</div>${warningHtml}<div class="ai-bubble"><pre>${esc(answer || 'Đang nhận dữ liệu...')}</pre></div>`;
  };

  const fallbackJson = async () => {
    const r = await fetch('/api/ai/remediation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q, data: G.data }),
      signal: controller.signal
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    renderAnswer(j, j.answer || '', j.latency_ms);
  };

  try {
    const r = await fetch('/api/ai/remediation/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q, data: G.data }),
      signal: controller.signal
    });
    if (!r.ok) {
      let message = `HTTP ${r.status}`;
      try {
        const j = await r.json();
        message = j.error || message;
      } catch (_) {}
      throw new Error(message);
    }
    if (!r.body || !window.TextDecoder) {
      await fallbackJson();
      return;
    }

    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const handleLine = (line) => {
      if (G.aiRequestId !== requestId) return;
      if (!line.trim()) return;
      const event = JSON.parse(line);
      if (!event.ok) throw new Error(event.error || 'AI stream error');
      if (event.event === 'meta') {
        meta = { ...meta, ...event };
        renderAnswer(meta, streamedAnswer, undefined);
      } else if (event.event === 'delta') {
        streamedAnswer += event.text || '';
        renderAnswer(meta, streamedAnswer, undefined);
      } else if (event.event === 'done') {
        renderAnswer(meta, streamedAnswer, event.latency_ms);
      } else if (event.event === 'error') {
        throw new Error(event.error || 'AI stream error');
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      lines.forEach(handleLine);
    }
    buffer += decoder.decode();
    if (buffer.trim()) handleLine(buffer);
  } catch(e) {
    if (e.name === 'AbortError') {
      renderAnswer(meta, streamedAnswer + (streamedAnswer ? '\n\n' : '') + '[Đã dừng theo yêu cầu]', undefined);
      return;
    }
    try {
      await fallbackJson();
    } catch (fallbackError) {
      if (fallbackError.name === 'AbortError') {
        renderAnswer(meta, streamedAnswer + (streamedAnswer ? '\n\n' : '') + '[Đã dừng theo yêu cầu]', undefined);
        return;
      }
      if (G.aiRequestId !== requestId) return;
      answerEl.innerHTML = `<span style="color:var(--red)">${esc(fallbackError.message || e.message)}</span>`;
      toast(fallbackError.message || e.message, 'err');
    }
  } finally {
    if (G.aiRequestId === requestId) {
      G.aiController = null;
      setAIControlsRunning(false);
    }
  }
}
