/* Theme preference is optional; the page remains usable when browser storage is blocked. */
(() => {
  const button = document.getElementById('theme-toggle');
  const root = document.documentElement;
  function syncLabel() {
    const dark = root.dataset.theme === 'dark';
    button.setAttribute('aria-label', dark ? 'Chuyển sang giao diện sáng' : 'Chuyển sang giao diện tối');
    button.setAttribute('aria-pressed', String(dark));
    button.title = dark ? 'Giao diện sáng' : 'Giao diện tối';
    document.querySelector('meta[name="theme-color"]').content = dark ? '#151b23' : '#f2f5f7';
  }
  button.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('ir_theme', root.dataset.theme); } catch (_) { /* session-only preference */ }
    syncLabel();
  });
  syncLabel();
})();
