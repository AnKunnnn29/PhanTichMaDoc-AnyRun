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
  document.getElementById('flow-status').textContent = G.data
    ? 'Đã có kết quả. Tiếp theo: kiểm tra chỉ báo và xem xét khuyến nghị.'
    : 'Chưa có dữ liệu. Bắt đầu bằng một báo cáo hoặc dữ liệu mẫu.';
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
        note.textContent = 'Trên bản web, hãy gửi mẫu để lấy Task ID. Khi Any.Run phân tích xong, dán ID vào mục Liên kết / Task ID để đọc kết quả.';
        document.getElementById('pane-' + pane).prepend(note);
      }
    }
  } catch (_) { /* Core navigation remains available offline. */ }
});
