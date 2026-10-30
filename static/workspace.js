/* Overview uses saved records only: no synthetic analytics or percentage gains. */
(() => {
  const state = {items: [], page: 0, size: 6};
  const nf = new Intl.NumberFormat('vi-VN');
  const date = new Intl.DateTimeFormat('vi-VN', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  const names = {critical:'Nghiêm trọng',high:'Cao',medium:'Cần kiểm tra',clean:'Không phát hiện',unknown:'Chưa xác định'};
  const colors = {critical:'#d44444',high:'#dc913c',medium:'#d6b94c',clean:'#279d7d',unknown:'#a7afbf'};
  const byId = id => document.getElementById(id);
  function priority(item) {
    if (!item.verdict || item.verdict === 'Unknown') return 'unknown';
    return Number(item.threat_level) >= 3 ? 'critical' : Number(item.threat_level) === 2 ? 'high' : Number(item.threat_level) === 1 ? 'medium' : item.verdict === 'Clean' ? 'clean' : 'unknown';
  }
  function review(item) {
    const actions = item.summary?.action_statuses ? item.summary.action_statuses.map(status=>({status})) : item.payload?.playbook?.actions || [];
    if (actions.some(a => a.status === 'changes_requested')) return 'Cần bổ sung';
    if (actions.some(a => a.status === 'pending')) return 'Chờ xem xét';
    return actions.length ? 'Đã xem xét' : 'Đã phân tích';
  }
  function demo(item) { return String(item.summary?.source || item.payload?.source || item.source || '').startsWith('demo'); }
  function render() {
    if (!byId('overview-stats')) return;
    const items = state.items;
    const refs = new Set();
    items.forEach(i => (i.summary?.observable_ids || (i.payload?.evidence_bundle?.observables || []).map(o=>o.id)).forEach(id => refs.add(id)));
    const pending = items.filter(i => ['Chờ xem xét','Cần bổ sung'].includes(review(i))).length;
    const urgent = items.filter(i => ['critical','high'].includes(priority(i))).length;
    byId('overview-stats').innerHTML = [
      ['Hồ sơ đã lưu',items.length,'Trong lịch sử hiện có'],
      ['Chờ xem xét',pending,'Hồ sơ còn khuyến nghị cần xử lý'],
      ['Chỉ báo duy nhất',refs.size,'Đối chiếu từ các hồ sơ có evidence'],
      ['Ưu tiên cao',urgent,'Đánh giá cao hoặc nghiêm trọng']
    ].map(([label,value,hint]) => `<div class="overview-stat" title="${escAttr(hint)}"><span>${label}</span><b>${nf.format(value)}</b></div>`).join('');
    const counts = Object.fromEntries(Object.keys(names).map(k => [k,items.filter(i => priority(i) === k).length]));
    byId('priority-distribution').innerHTML = `<div class="priority-meter" aria-hidden="true">${Object.keys(names).map(k => `<i style="width:${items.length ? counts[k]/items.length*100 : 0}%;background:${colors[k]}"></i>`).join('')}</div>` + Object.keys(names).map(k => `<div class="priority-row"><i style="background:${colors[k]}"></i><span>${names[k]}</span><b>${nf.format(counts[k])}</b></div>`).join('');
    renderChart(); renderRows(); renderCurrent();
  }
  function renderCurrent() {
    const root = byId('overview-current');
    if (!root) return;
    const data = G.data;
    root.replaceChildren();
    root.hidden = !data;
    if (!data) return;
    const name = document.createElement('strong');
    name.textContent = data.file?.name || data.playbook?.malware_name || 'Hồ sơ';
    const controls = document.createElement('div');
    controls.className = 'overview-current-actions';
    const pending = (data.playbook?.actions || []).filter(a => ['pending','changes_requested'].includes(a.status)).length;
    const status = document.createElement('span');
    status.textContent = `${pending} khuyến nghị chờ xem xét`;
    const open = document.createElement('button');
    open.type = 'button'; open.className = 'btn btn-outline';
    open.textContent = 'Tiếp tục →';
    open.addEventListener('click', () => goToResult('playbook'));
    controls.append(status, open); root.append(name, controls);
  }
  function renderChart() {
    const days = Number(byId('activity-period').value);
    const buckets = Array.from({length:days},(_,n) => {const d=new Date(); d.setHours(0,0,0,0); d.setDate(d.getDate()-(days-1-n)); return {date:d,count:0};});
    state.items.forEach(item => {const d=new Date(item.created_at); d.setHours(0,0,0,0); const b=buckets.find(b=>b.date.getTime()===d.getTime()); if(b)b.count++;});
    const max = Math.max(1,...buckets.map(b=>b.count));
    byId('activity-chart').innerHTML = buckets.map((b,n) => `<div class="activity-column" title="${escAttr(b.date.toLocaleDateString('vi-VN'))}: ${b.count} hồ sơ"><span>${b.count || ''}</span><i style="height:${b.count/max*135}px"></i>${n===0 || n===days-1 || n===Math.floor(days/2) ? `<small>${esc(b.date.toLocaleDateString('vi-VN',{day:'2-digit',month:'2-digit'}))}</small>` : ''}</div>`).join('');
    const total = buckets.reduce((sum,b)=>sum+b.count,0);
    byId('activity-total').textContent = `${nf.format(total)} hồ sơ trong ${days} ngày`;
    byId('activity-chart').setAttribute('aria-label', buckets.map(b=>`${b.date.toLocaleDateString('vi-VN')}: ${b.count} hồ sơ`).join('; '));
  }
  function renderRows() {
    const term = byId('case-search').value.trim().toLocaleLowerCase('vi');
    const filter = byId('case-filter').value;
    const items = state.items.filter(i => [i.file_name,i.malware_name,...(i.hashes || [])].join(' ').toLocaleLowerCase('vi').includes(term))
      .filter(i => filter==='all' || filter==='demo' && demo(i) || filter==='critical' && ['critical','high'].includes(priority(i)) || filter==='review' && ['Chờ xem xét','Cần bổ sung'].includes(review(i)));
    state.page = Math.min(state.page,Math.max(0,Math.ceil(items.length/state.size)-1));
    const start = state.page*state.size;
    const rows = items.slice(start,start+state.size);
    const body = byId('recent-cases');
    body.innerHTML = rows.map(i => {
      const p=priority(i),d=new Date(i.created_at);
      return `<tr><td><button type="button" class="case-name" data-open-case="${escAttr(i.id)}" title="${escAttr(i.file_name || i.malware_name)}">${esc(i.file_name || 'Báo cáo không tên')}</button><div class="case-sub">${demo(i)?'Dữ liệu mẫu':'Báo cáo nhập'}${i.hashes?.length?' · '+esc(String(i.hashes[0]).slice(0,12))+'…':''}</div></td><td>${esc(i.malware_name || 'Chưa phân loại')}</td><td><span class="case-pill ${p}">${names[p]}</span></td><td><span class="case-pill">${review(i)}</span></td><td style="white-space:nowrap;color:var(--text2)">${isNaN(d.getTime())?'—':esc(date.format(d))}</td></tr>`;
    }).join('') || '<tr><td colspan="5" style="padding:32px;text-align:center;color:var(--text2)">Không có hồ sơ phù hợp. Thử đổi bộ lọc hoặc nhập báo cáo mới.</td></tr>';
    body.querySelectorAll('[data-open-case]').forEach(button => button.addEventListener('click',()=>analyzeLocalHistory(encodeURIComponent(button.dataset.openCase))));
    byId('case-page-info').textContent = items.length ? `${start+1}–${Math.min(start+state.size,items.length)} / ${nf.format(items.length)} hồ sơ` : '0 hồ sơ';
    byId('cases-prev').disabled = state.page === 0;
    byId('cases-next').disabled = start+state.size >= items.length;
  }
  window.WorkspaceUI = {
    setError() {
      byId('recent-cases').innerHTML = '<tr><td colspan="5" style="padding:24px;text-align:center">Không tải được hồ sơ. Chọn Làm mới để thử lại.</td></tr>';
      byId('case-page-info').textContent = 'Chưa tải được dữ liệu';
      byId('cases-prev').disabled = true;
      byId('cases-next').disabled = true;
    },
    setHistory(items) {state.items=[...items].sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)); render();},
    updateCurrent: renderCurrent,
    focusSearch() {showPage('overview',document.querySelector('[data-page="overview"]')); byId('case-search').focus(); byId('case-search').scrollIntoView({block:'center'});}
  };
  window.addEventListener('load',()=>{
    byId('case-search').addEventListener('input',()=>{state.page=0;renderRows();});
    byId('case-filter').addEventListener('change',()=>{state.page=0;renderRows();});
    byId('activity-period').addEventListener('change',renderChart);
    byId('cases-prev').addEventListener('click',()=>{state.page--;renderRows();});
    byId('cases-next').addEventListener('click',()=>{state.page++;renderRows();});
  });
  document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();window.WorkspaceUI.focusSearch();}});
})();
