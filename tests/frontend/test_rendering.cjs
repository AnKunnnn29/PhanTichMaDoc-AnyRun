// Pure rendering tests: no browser, network, or third-party packages.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../../static/app.js'), 'utf8');
const context = { URL };
function section(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a);
  assert(a >= 0 && b > a, 'Rendering function boundaries must exist');
  return source.slice(a, b);
}
vm.runInNewContext(
  section('function esc(s)', 'function renderEvidencePanel') +
  section('function safeLink(value)', 'function renderAIProactive') +
  section('function formatAssistantAnswer(value)', 'function setAIControlsRunning'), context);
const html = context.formatAssistantAnswer('## Evidence\n**Observed**\n<img src=x onerror=alert(1)>\n```html\n<script>alert(1)</script>\n```');
assert(html.includes('<h4>Evidence</h4>'));
assert(html.includes('<strong>Observed</strong>'));
assert(!html.includes('<img') && !html.includes('<script>'));
assert(html.includes('&lt;script&gt;'));
assert.equal(context.safeLink('javascript:alert(1)'), '#');
assert.equal(context.safeLink('data:text/html,test'), '#');
assert(context.safeLink('https://example.com/').startsWith('https://example.com'));
assert(context.formatAssistantAnswer('```\nunfinished').includes('</code></pre>'));
console.log('Frontend rendering and URL guards passed.');
