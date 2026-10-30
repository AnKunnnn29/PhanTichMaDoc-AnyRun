const responseState = {phase:'all', limit:6};
const reviewLabels = {pending:'Chờ xem xét',approved:'Đã duyệt đề xuất',rejected:'Đã từ chối',changes_requested:'Cần bổ sung'};
const agentDecisionLabels = {recommend:'Agent: nên thực hiện',defer:'Agent: tạm hoãn',not_applicable:'Agent: không áp dụng',unassessed:'Agent: chưa đánh giá'};
const agentDecisionOrder = {recommend:0,unassessed:1,defer:2,not_applicable:3};
function selectResponsePhase(phase) { responseState.phase=phase; responseState.limit=6; renderResponsePlan(G.data); }
function reviewResponse(id) {
  const select=document.querySelector('#review-content select');
  if (select) {select.value=id; select.dispatchEvent(new Event('change'));}
  document.getElementById('review-content').scrollIntoView({behavior:'smooth',block:'start'});
  document.querySelector('#review-content input')?.focus({preventScroll:true});
}
function renderResponsePlan(data) {
  const root=document.getElementById('playbook-content');
  const actions=data.playbook?.actions || [];
  const phases=[...new Set(actions.map(a=>a.phase))];
  if (!phases.includes(responseState.phase)) responseState.phase='all';
  // The agent's decision only orders the list; every action still needs analyst review.
  const filtered=actions.filter(a=>responseState.phase==='all'||a.phase===responseState.phase)
    .map((a,n)=>[a,n]).sort(([a,i],[b,j])=>(agentDecisionOrder[a.agent_decision]??1)-(agentDecisionOrder[b.agent_decision]??1)||(a.agent_priority||a.priority)-(b.agent_priority||b.priority)||i-j).map(([a])=>a);
  const decided=d=>actions.filter(a=>a.agent_decision===d).length;
  const agentMode=data.case_agent?.mode;
  const phaseName=p=>({'Identification':'Xác minh','Containment':'Ngăn chặn','Eradication':'Loại bỏ','Recovery':'Phục hồi','Lessons Learned':'Rút kinh nghiệm'}[p.match(/Identification|Containment|Eradication|Recovery|Lessons Learned/)?.[0]]||p);
  const list=items=>'<ol>'+items.map(item=>'<li>'+esc(item)+'</li>').join('')+'</ol>';
  root.innerHTML=`<section class="response-overview">
    <div><span class="response-kicker">Kế hoạch xử lý · ${esc(data.playbook.malware_name)}</span><h3>Xác minh đúng đích. Xử lý từng bước.</h3><p>${actions.length} đề xuất · ${actions.filter(a=>a.priority===1).length} ưu tiên cao nhất · ${actions.filter(a=>a.status==='approved').length} đề xuất đã duyệt</p>${agentMode?`<p>Agent điều tra (${agentMode==='llm'?'AI':agentMode==='fallback'?'AI lỗi, dùng quy tắc':'quy tắc'}): ${decided('recommend')} nên thực hiện · ${decided('defer')} tạm hoãn · ${decided('not_applicable')} không áp dụng. Danh sách đã sắp theo đánh giá này.</p>`:''}</div>
    <button type="button" class="btn btn-outline" onclick="showPage('evidence',document.querySelector('[data-page=evidence]'))">Đối chiếu bằng chứng →</button>
    </section>
    <p class="response-boundary">Báo cáo sandbox chưa xác nhận máy nào trong tổ chức đã nhiễm. Duyệt đề xuất là quyết định xem xét, chưa có nghĩa biện pháp đã thực thi.</p>
    <div class="response-filters" role="group" aria-label="Lọc giai đoạn xử lý">${['all',...phases].map(p=>`<button type="button" aria-pressed="${p===responseState.phase}" class="${p===responseState.phase?'selected':''}" onclick="selectResponsePhase(decodeURIComponent('${encodeURIComponent(p).replace(/'/g,'%27')}'))">${p==='all'?'Tất cả':esc(phaseName(p))}<span>${p==='all'?actions.length:actions.filter(a=>a.phase===p).length}</span></button>`).join('')}</div>
    <div class="response-actions">${filtered.slice(0,responseState.limit).map((a,index)=>{
      const steps=a.steps?.length?a.steps:['Phân tích lại hồ sơ để có hướng dẫn theo từng bước.'];
      return `<article class="response-action" id="response-${escAttr(a.id)}">
        <header><span class="response-number">${String(index+1).padStart(2,'0')}</span><div><div class="response-meta"><span class="response-priority priority-${a.priority}">Ưu tiên ${a.priority}</span><span>${esc(phaseName(a.phase))}</span><span>${esc(reviewLabels[a.status]||'Chờ xem xét')}</span>${a.agent_decision?`<span class="agent-decision agent-${escAttr(a.agent_decision)}">${esc(agentDecisionLabels[a.agent_decision]||a.agent_decision)}${a.agent_priority?' · ưu tiên '+a.agent_priority:''}</span>`:''}</div><h4>${esc(a.title)}</h4></div></header>
        ${a.agent_rationale?`<p class="agent-rationale"><b>Lý do của Agent:</b> ${esc(a.agent_rationale)}${(a.agent_evidence_ids||[]).length?` <span>(${a.agent_evidence_ids.length} evidence)</span>`:''}</p>`:''}
        <p class="response-origin ${a.origin==='case_specific'?'origin-case':'origin-template'}">${a.origin==='case_specific'?'Riêng cho ca này: dựng từ dữ kiện và bằng chứng của hồ sơ':'Mẫu chung: chưa có dữ kiện cụ thể trong hồ sơ cho bước này'}</p>
        <p class="response-objective">${esc(a.objective||productDescription(a.description))}</p>
        <details class="response-detail" ${index===0?'open':''}><summary>Xem các bước &amp; tiêu chí kiểm tra</summary><div class="response-scope"><b>Đối tượng áp dụng</b><p>${esc(a.target_scope||'Cần xác minh đối tượng trên endpoint thực tế.')}</p></div>
        <div class="response-procedure"><section>${a.origin==='case_specific'&&(a.preconditions||[]).length?`<h5>Xác minh trước khi làm</h5>${list(a.preconditions)}`:''}<h5>Cách thực hiện</h5>${list(steps)}</section><section class="response-verification"><h5>Khi nào có thể hoàn tất?</h5>${list(a.verification||a.evidence_required||[])}<h5>Nếu phát sinh ảnh hưởng</h5><p>${esc(a.rollback||'Dừng thay đổi và xin quyết định của người phụ trách sự cố.')}</p></section></div>
        <details class="response-evidence"><summary>Nguồn tham chiếu &amp; điều kiện áp dụng (${(a.evidence_ids||[]).length})</summary><p>Đây là bằng chứng ứng viên; cần kiểm tra quan hệ với biện pháp trước khi áp dụng.</p>${list(a.preconditions||[])}<ul>${(a.related_observations||[]).map(o=>`<li><b>${esc(o.type)}</b> · ${esc(o.value)}</li>`).join('')}</ul>${a.blocked?'<p class="response-missing">Thiếu bằng chứng để đề xuất thao tác. Bổ sung nguồn trước khi duyệt.</p>':''}</details>
        ${a.commands?.length?`<details class="response-commands"><summary>Lệnh tham khảo · cần xác minh đích và sửa theo môi trường</summary><p>Các lệnh dưới đây là mẫu kỹ thuật từ playbook, không phải lệnh sẵn sàng chạy. Ưu tiên quy trình EDR/ITSM của tổ chức và các bước đã duyệt ở trên.</p><pre>${esc(a.commands.join('\n'))}</pre></details>`:''}
        </details><footer><span>Phụ trách đề xuất: ${esc(a.owner||'Cần phân công')} · Mục tiêu thời gian tham khảo: ${esc(a.sla||'Cần thống nhất')}</span><button type="button" class="btn btn-outline" onclick="reviewResponse('${escAttr(a.id)}')">Xem xét đề xuất</button></footer>
      </article>`;
    }).join('')}</div>
    ${filtered.length>responseState.limit?'<button type="button" class="btn btn-outline" onclick="responseState.limit+=6;renderResponsePlan(G.data)">Xem thêm biện pháp ('+(filtered.length-responseState.limit)+')</button>':''}`;
}
