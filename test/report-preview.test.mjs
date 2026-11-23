import test from 'node:test';
import assert from 'node:assert/strict';
import { renderA4Document, renderA4Sheet } from '../src/report-preview.mjs';

test('A4 preview uses real issue counts and positions, and keeps a bounded printable summary', () => {
  const finding = (id, line) => ({ ruleId: `SRC-${id}`, cwe: 'CWE-89', severity: 'high', title: `Finding ${id}`,
    location: { file: 'app.js', line }, evidence: `db.query(value${line});`, impact: 'Needs review', remediation: 'Bind SQL parameters.' });
  const report = { target: 'Upload: demo.zip', startedAt: '2026-11-23T14:00:00Z', status: 'complete', stats: {},
    findings: [finding('SQL', 2), finding('SQL', 4), finding('SQL', 6), ...[1, 2, 3, 4].map((id) => finding(id, id + 10))] };
  const html = renderA4Sheet(report, { title: '<script>review</script>' }, true);
  assert.equal((html.match(/class="a4-issue /g) ?? []).length, 4);
  assert.match(html, /app\.js:2[\s\S]*db\.query\(value2\)/);
  assert.match(html, /app\.js:4[\s\S]*db\.query\(value4\)/);
  assert.match(html, /1 vị trí khác/);
  assert.match(html, /1 nhóm khác/);
  assert.match(html, /5 nhóm phát hiện/);
  assert.match(html, /&lt;script&gt;review&lt;\/script&gt;/);
  assert.match(html, /contenteditable="plaintext-only"/);
  const exported = renderA4Document(report, 'body{margin:0}', { title: 'Báo cáo đã chỉnh sửa' });
  assert.match(exported, /lang="vi"/);
  assert.match(exported, /Báo cáo đã chỉnh sửa/);
  assert.doesNotMatch(exported, /contenteditable|<script/);
});

test('empty incomplete scan reports limited coverage without an invented safety score', () => {
  const html = renderA4Sheet({ target: 'sample', status: 'partial', stats: { sourceAnalysis: { mode: 'deep' } }, findings: [] });
  assert.match(html, /Deep Scan with Semgrep/);
  assert.match(html, /Phạm vi chưa đầy đủ/);
  assert.match(html, /Chưa ghi nhận phát hiện/);
  assert.doesNotMatch(html, /\/100/);
});
