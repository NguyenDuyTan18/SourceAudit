import test from 'node:test';
import assert from 'node:assert/strict';
import { createReport, finishReport, renderHtml, renderText } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';

test('readable reports show a repeated issue once and retain each distinct location and statement', () => {
  const report = createReport('source', 'Project <review>');
  const finding = (file, line, statement) => ({
    ruleId: 'SRC-SQL', cwe: 'CWE-89', severity: 'high', title: 'SQL query needs review',
    status: 'needs-review', confidence: 'medium', location: { file, line },
    evidence: statement, impact: 'The query may use untrusted input.', remediation: 'Bind the values separately.',
  });
  const first = { ...finding('app.js', 12, 'db.query(sql);'), trace: [{ file: 'app.js', line: 8, role: 'source', evidence: 'input' }] };
  const second = { ...finding('api.js', 31, 'db.query(filter);'), trace: [{ file: 'api.js', line: 25, role: 'source', evidence: 'filter' }] };
  report.findings.push(first, { ...first }, second);
  report.findings.push({ ...finding('api.js', 44, 'db.query(options);'), ruleId: 'SC-JS-SQL-LITERAL', title: 'Raw SQL expression' });
  finishReport(report);

  const html = renderHtml(report);
  assert.match(html, /Quick Scan/);
  assert.match(html, /@page\s*\{\s*size:\s*A4/);
  assert.match(html, /Project &lt;review&gt;/);
  assert.equal((html.match(/SQL query needs review/g) ?? []).length, 1);
  assert.equal((html.match(/app\.js:12/g) ?? []).length, 1);
  assert.match(html, /app\.js:12[\s\S]*db\.query\(sql\)/);
  assert.match(html, /api\.js:31[\s\S]*db\.query\(filter\)/);
  assert.match(html, /Data-flow trace[\s\S]*app\.js:8[\s\S]*api\.js:25/);
  assert.match(html, /Raw SQL expression/);

  const text = renderText(report);
  assert.equal((text.match(/SQL query needs review/g) ?? []).length, 1);
  assert.match(text, /app\.js:12[\s\S]*db\.query\(sql\)/);
  assert.match(text, /api\.js:31[\s\S]*db\.query\(filter\)/);
  assert.equal(renderSarif(report).runs[0].results.length, 4);
});

test('Semgrep reports identify the engine and show the flagged redacted source line first', () => {
  const report = createReport('source', 'sample');
  report.stats = { sourceAnalysis: { engine: 'Semgrep', mode: 'deep', status: 'complete', scanned: 1, selected: 1, findings: 1 } };
  report.findings.push({ ruleId: 'example-rule', cwe: 'CWE-89', severity: 'high', title: 'Query review',
    location: { file: 'app.js', line: 9, column: 4 }, evidence: 'Engine message',
    sourceExcerpt: '  8 | // nearby comment\n> 9 | db.query(…);\n  10 | return;',
  });
  finishReport(report);
  const html = renderHtml(report);
  assert.match(html, /Deep Scan with Semgrep/);
  assert.match(html, /app\.js:9:4[\s\S]*db\.query\(…\);/);
  assert.doesNotMatch(html.match(/<pre class="statement">([\s\S]*?)<\/pre>/)?.[1] ?? '', /nearby comment/);
});
