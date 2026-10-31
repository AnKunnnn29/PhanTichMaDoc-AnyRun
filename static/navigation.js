/* Screen and input-tab routing. All transitions preserve the open case in memory. */
const PAGE_PATHS = Object.freeze(Object.fromEntries(
  ['overview','home','analyze','dashboard','playbook','evidence','iocs','history'].map(id => [id, '/' + id])
));
const ANALYSIS_TABS = ['uuid','import','url','file','ghidra','demo'];
function currentAnalysisTab() {
  return document.querySelector('#page-analyze [role="tab"].active')?.id.replace('tab-', '') || 'import';
}
function restorePageFromLocation() {
  const path = location.pathname.replace(/\/$/, '') || '/';
  const inputTab = path.startsWith('/analyze/') ? path.split('/')[2] : null;
  const id = inputTab ? 'analyze' : Object.keys(PAGE_PATHS).find(id => PAGE_PATHS[id] === path) || 'overview';
  showPage(id, null, false);
  if (id === 'analyze') switchTab('tab-' + (ANALYSIS_TABS.includes(inputTab) ? inputTab : 'import'), false);
}
function showPage(id, el, updateHistory = true) {
  const target = document.getElementById('page-' + id);
  if (!PAGE_PATHS[id] || !target) return;
  const path = id === 'analyze' ? '/analyze/' + currentAnalysisTab() : PAGE_PATHS[id];
  if (updateHistory && location.pathname !== path) history.pushState({page:id}, '', path);
  if (typeof updateGuide === 'function') updateGuide();
  const pageLabel = document.getElementById('workspace-page-label');
  if (pageLabel) pageLabel.textContent = ({overview:'Tổng quan',home:'Bắt đầu',dashboard:'Kết quả phân tích',analyze:'Phân tích mới',playbook:'Kế hoạch khắc phục',evidence:'Bằng chứng nguồn',iocs:'IOC & SIEM',history:'Lịch sử'})[id];
  document.querySelectorAll('[id^="page-"]').forEach(page => {
    page.style.display = page === target ? 'block' : 'none';
    page.classList.remove('page-enter');
  });
  document.querySelectorAll('.nav-item').forEach(item => {
    const active = item.dataset.page === id;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  void target.offsetWidth;
  target.classList.add('page-enter');
  if (typeof animateCards === 'function') animateCards(target);
  window.scrollTo({top:0,behavior:'instant'});
}
function switchTab(id, updateHistory = true) {
  const tab = id.replace('tab-', '');
  if (!ANALYSIS_TABS.includes(tab)) return;
  if (updateHistory) {
    showPage('analyze', null, false);
    const path = '/analyze/' + tab;
    if (location.pathname !== path) history.pushState({page:'analyze',tab}, '', path);
  }
  document.querySelectorAll('#page-analyze [role="tab"]').forEach(item => {
    const active = item.id === id;
    item.classList.toggle('active', active);
    item.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('#page-analyze [role="tabpanel"]').forEach(pane => {
    const active = pane.id === 'pane-' + tab;
    pane.classList.toggle('active', active);
    pane.hidden = !active;
  });
}
window.addEventListener('popstate', restorePageFromLocation);
document.addEventListener('DOMContentLoaded', restorePageFromLocation);
