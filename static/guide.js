/* The four steps follow the actual report -> evidence -> review -> export flow. */
function startAnalysis(tab = 'import') {
  showPage('analyze', document.querySelector('[data-page="analyze"]'));
  switchTab('tab-' + tab);
}
function goToResult(page) {
  if (!G.data) {
    toast('Hãy nhập báo cáo hoặc dùng thử dữ liệu mẫu trước.', 'err');
    startAnalysis();
    return;
  }
  showPage(page, document.querySelector('[data-page="' + page + '"]'));
}
function updateGuide() {
  document.querySelectorAll('[data-needs-analysis]').forEach(button => {
    button.disabled = !G.data;
    button.title = G.data ? '' : 'Nhập báo cáo hoặc dùng thử dữ liệu mẫu trước';
  });
  const status = document.getElementById('flow-status');
  status.replaceChildren();
  if (!G.data) {
    status.textContent = 'Chưa mở hồ sơ.';
    return;
  }
  // A case reopened from the last visit is named, so the chat context is never a surprise.
  const name = G.data.file?.name || G.data.playbook?.malware_name || 'hồ sơ';
  status.append(`${name}${G.restored ? ' · Đã khôi phục' : ''} `);
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'btn btn-outline';
  close.textContent = 'Đóng hồ sơ';
  close.addEventListener('click', closeCase);
  status.append(close);
}
function closeCase() {
  try { localStorage.removeItem(LAST_ANALYSIS_KEY); localStorage.setItem(CASE_CLOSED_KEY, '1'); } catch (_) { /* storage may be blocked */ }
  G.data = null;
  G.restored = false;
  if (typeof clearChat === 'function') clearChat();
  document.getElementById('chat-case-name').textContent = 'Chưa mở hồ sơ';
  updateGuide();
  if (window.WorkspaceUI?.updateCurrent) WorkspaceUI.updateCurrent();
  toast('Đã đóng hồ sơ. Lịch sử vẫn giữ để mở lại khi cần.');
}
window.addEventListener('load', async () => {
  updateGuide();
  try {
    const result = await (await fetch('/api/config')).json();
    if (result.data?.cloud_mode) {
      document.body.classList.add('cloud-mode');
      document.getElementById('cloud-notice').hidden = false;
      document.getElementById('tab-ghidra').disabled = true;
      document.getElementById('tab-ghidra').title = 'Ghidra cần chạy bản trên máy tính';
      document.querySelectorAll('[onclick="submitAnalyzeURL()"], [onclick="submitAnalyzeFile()"]').forEach(button => {
        button.disabled = true;
        button.title = 'Bản web: chọn gửi lấy Task ID, rồi lấy kết quả sau khi sandbox hoàn tất';
      });
      for (const pane of ['url', 'file']) {
        const note = document.createElement('p');
        note.className = 'help-note';
        note.textContent = 'Gửi mẫu lấy Task ID; nhập ID khi sandbox phân tích xong.';
        document.getElementById('pane-' + pane).prepend(note);
      }
    }
  } catch (_) { /* Core navigation remains available offline. */ }
});
